package taint

import (
	"reflect"
	"testing"
)

// Unknown keys intentionally remain may-matches. These cases do not require
// generalized SSA-identity kills or helper control-flow composition.
func TestSelectedMapKeyIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, helpers, body string
		want                int
	}{
		{"int_int64_delete", ``, `m:=map[any]string{int(1):source()};delete(m,int64(1));sink(m[int(1)])`, 1},
		{"int_int64_overwrite", ``, `m:=map[any]string{int(1):source()};m[int64(1)]="safe";sink(m[int(1)])`, 1},
		{"int_int64_write_filter", ``, `m:=map[any]string{int64(1):source()};sink(m[int(1)])`, 0},
		{"named_string_delete", `type K string`, `m:=map[any]string{K("q"):source()};delete(m,"q");sink(m[K("q")])`, 1},
		{"named_string_cast_delete", `type K string`, `k:="q";m:=map[any]string{"q":source()};delete(m,K(k));sink(m["q"])`, 1},
		{"named_string_cast_write_filter", `type K string`, `k:="q";m:=map[any]string{K(k):source()};sink(m["q"])`, 0},
		{"named_same_cast_delete", `type K string`, `k:="q";m:=map[any]string{K("q"):source()};delete(m,K(k));sink(m[K("q")])`, 0},
		{"two_named_strings_delete", `type K string;type L string`, `m:=map[any]string{K("q"):source()};delete(m,L("q"));sink(m[K("q")])`, 1},
		{"string_alias_delete", `type K = string`, `m:=map[any]string{"q":source()};delete(m,K("q"));sink(m["q"])`, 0},
		{"byte_alias_delete", ``, `m:=map[any]string{byte(1):source()};delete(m,uint8(1));sink(m[byte(1)])`, 0},
		{"rune_alias_delete", ``, `m:=map[any]string{rune(1):source()};delete(m,int32(1));sink(m[rune(1)])`, 0},
		{"helper_string_delete", `func drop(m map[any]string,k string){delete(m,k)}`, `m:=map[any]string{"q":source()};drop(m,"q");sink(m["q"])`, 0},
		{"helper_string_write_filter", `func put(m map[any]string,k,v string){m[k]=v}`, `m:=map[any]string{};put(m,"other",source());sink(m["q"])`, 0},
		{"helper_named_delete", `type K string;func drop(m map[any]string,k string){delete(m,K(k))}`, `m:=map[any]string{"q":source()};drop(m,"q");sink(m["q"])`, 1},
		{"helper_named_same_delete", `type K string;func drop(m map[any]string,k string){delete(m,K(k))}`, `m:=map[any]string{K("q"):source()};drop(m,"q");sink(m[K("q")])`, 0},
		{"nested_any_delete", `func drop(m map[any]string,k any){delete(m,k)};func outer(m map[any]string,k string){drop(m,k)}`, `m:=map[any]string{"q":source()};outer(m,"q");sink(m["q"])`, 0},
		{"three_level_any_delete", `func drop(m map[any]string,k any){delete(m,k)};func mid(m map[any]string,k any){drop(m,k)};func outer(m map[any]string,k string){mid(m,k)}`, `m:=map[any]string{"q":source()};outer(m,"q");sink(m["q"])`, 0},
		{"nested_named_write_filter", `type K string;func put(m map[any]string,k any,v string){m[k]=v};func outer(m map[any]string,k string,v string){put(m,K(k),v)}`, `m:=map[any]string{};outer(m,"q",source());sink(m["q"])`, 0},
		{"change_interface_named_delete", `type K string;func(K)M(){};type I interface{M()}`, `var a I=K("q");var b any=a;m:=map[any]string{K("q"):source()};delete(m,b);sink(m[K("q")])`, 0},
		{"change_interface_named_distinct", `type K string;func(K)M(){};type I interface{M()}`, `var a I=K("q");var b any=a;m:=map[any]string{"q":source()};delete(m,b);sink(m["q"])`, 1},
		{"helper_parameter_load_delete", `func hold(*string){};func drop(m map[any]string,k string){p:=&k;hold(p);delete(m,*p)}`, `m:=map[any]string{"q":source()};drop(m,"q");sink(m["q"])`, 0},
		{"helper_parameter_swap", `func drop(m map[any]string,a,b string){delete(m,b)};func outer(m map[any]string,a,b string){drop(m,b,a)}`, `m:=map[any]string{"q":source()};outer(m,"other","q");sink(m["q"])`, 1},
		{"phi_mixed_types_delete", ``, `var k any=int(1);if flag(){k=int64(1)};m:=map[any]string{int(1):source()};delete(m,k);sink(m[int(1)])`, 1},
		{"phi_same_types_delete", ``, `var k any=int(1);if flag(){k=int(1)};m:=map[any]string{int(1):source()};delete(m,k);sink(m[int(1)])`, 0},
		{"phi_mixed_named_delete", `type K string`, `var k any="q";if flag(){k=K("q")};m:=map[any]string{"q":source()};delete(m,k);sink(m["q"])`, 1},
		{"load_mixed_types_delete", `func hold(*any){}`, `p:=new(any);*p=int(1);if flag(){*p=int64(1)};hold(p);m:=map[any]string{int(1):source()};delete(m,*p);sink(m[int(1)])`, 1},
		{"load_same_types_delete", `func hold(*any){}`, `p:=new(any);*p=int(1);if flag(){*p=int(1)};hold(p);m:=map[any]string{int(1):source()};delete(m,*p);sink(m[int(1)])`, 0},
		{"int8_wrap_write", ``, `x:=257;m:=map[int8]string{int8(x):source()};sink(m[1])`, 1},
		{"uint8_wrap_write", ``, `x:=-1;m:=map[uint8]string{uint8(x):source()};sink(m[255])`, 1},
		{"narrowing_roundtrip_delete", ``, `x:=257;m:=map[int]string{257:source()};delete(m,int(int8(x)));sink(m[257])`, 1},
		{"float32_round_write", ``, `x:=16777217;m:=map[float32]string{float32(x):source()};sink(m[16777216])`, 1},
		{"float64_round_write", ``, `x:=int64(9007199254740993);m:=map[float64]string{float64(x):source()};sink(m[9007199254740992])`, 1},
		{"float_roundtrip_delete", ``, `x:=float64(16777217);m:=map[float64]string{16777217:source()};delete(m,float64(float32(x)));sink(m[16777217])`, 1},
		{"float_int_write", ``, `x:=1.9;m:=map[int]string{int(x):source()};sink(m[1])`, 1},
		{"rune_string_write", ``, `x:=113;m:=map[string]string{string(rune(x)):source()};sink(m["q"])`, 1},
		{"helper_numeric_wrap_write", `func put(m map[int8]string,k int,v string){m[int8(k)]=v}`, `m:=map[int8]string{};put(m,257,source());sink(m[1])`, 1},
		{"finite_float_delete", ``, `m:=map[float64]string{1.5:source()};delete(m,1.5);sink(m[1.5])`, 0},
		{"finite_complex_delete", ``, `m:=map[complex128]string{1+2i:source()};delete(m,1+2i);sink(m[1+2i])`, 0},
		{"finite_float_interface_types", ``, `m:=map[any]string{float32(1):source()};delete(m,float64(1));sink(m[float32(1)])`, 1},
		{"finite_complex_interface_types", ``, `m:=map[any]string{complex64(1+2i):source()};delete(m,complex128(1+2i));sink(m[complex64(1+2i)])`, 1},
		{"dynamic_nan_delete_weak", ``, `k:=float64(0);k/=k;m:=map[float64]string{1:source()};delete(m,k);sink(m[1])`, 1},
		{"dynamic_array_delete_weak", ``, `k:=[1]int{1};m:=map[[1]int]string{k:source()};delete(m,k);sink(m[k])`, 1},
		{"dynamic_struct_delete_weak", ``, `k:=struct{i int}{1};m:=map[struct{i int}]string{k:source()};delete(m,k);sink(m[k])`, 1},
		{"assert_different_named_delete_weak", `type K string`, `var k any=K("q");m:=map[any]string{"q":source()};delete(m,k.(K));sink(m["q"])`, 1},
		{"comma_ok_assert_delete_weak", `type K string`, `var k any=K("q");a,_:=k.(K);m:=map[any]string{"q":source()};delete(m,a);sink(m["q"])`, 1},
		{"helper_distinct_integer_delete", `func drop(m map[any]string){delete(m,int64(1))}`, `m:=map[any]string{int(1):source()};drop(m);sink(m[int(1)])`, 1},
		{"nested_distinct_integer_delete", `func drop(m map[any]string){delete(m,int64(1))};func outer(m map[any]string){drop(m)}`, `m:=map[any]string{int(1):source()};outer(m);sink(m[int(1)])`, 1},
		{"nested_same_integer_delete", `func drop(m map[any]string){delete(m,int64(1))};func outer(m map[any]string){drop(m)}`, `m:=map[any]string{int64(1):source()};outer(m);sink(m[int64(1)])`, 0},
		{"helper_named_map_key", `type K string;func drop(m map[K]string,k K){delete(m,k)}`, `m:=map[K]string{"q":source()};drop(m,"q");sink(m["q"])`, 0},
		{"helper_interface_named_type", `type K string;type I interface{ String() string };func(K)String()string{return "k"};func drop(m map[I]string,k K){delete(m,k)}`, `m:=map[I]string{K("q"):source()};drop(m,"q");sink(m[K("q")])`, 0},
		{"helper_change_interface", `type K string;type I interface{ String() string };func(K)String()string{return "k"};func drop(m map[any]string,k I){delete(m,k)}`, `m:=map[any]string{K("q"):source()};drop(m,K("q"));sink(m[K("q")])`, 0},
		{"helper_named_interface_change_type", `type K string;type I interface{ String() string };type J I;func(K)String()string{return "k"};func drop(m map[any]string,k I){delete(m,J(k))}`, `m:=map[any]string{K("q"):source()};drop(m,K("q"));sink(m[K("q")])`, 0},
		{"assert_known_same_delete", ``, `var k any="q";m:=map[any]string{"q":source()};delete(m,k.(string));sink(m["q"])`, 0},
		{"assert_comma_ok_same_delete", ``, `var k any="q";a,_:=k.(string);m:=map[any]string{"q":source()};delete(m,a);sink(m["q"])`, 0},
		{"assert_comma_ok_failure_weak", ``, `var k any=1;a,_:=k.(string);m:=map[any]string{"q":source()};delete(m,a);sink(m["q"])`, 1},
		{"helper_assert_known_same_delete", `func drop(m map[any]string,k any){delete(m,k.(string))}`, `m:=map[any]string{"q":source()};drop(m,"q");sink(m["q"])`, 0},
		{"helper_assert_comma_ok_same_delete", `func drop(m map[any]string,k any){a,_:=k.(string);delete(m,a)}`, `m:=map[any]string{"q":source()};drop(m,"q");sink(m["q"])`, 0},
		{"helper_wrapped_write_match", `func put(m map[any]string,k,v string){m[k]=v}`, `m:=map[any]string{};put(m,"q",source());sink(m["q"])`, 1},
		{"nested_wrapped_write_match", `func put(m map[any]string,k any,v string){m[k]=v};func outer(m map[any]string,k,v string){put(m,k,v)}`, `m:=map[any]string{};outer(m,"q",source());sink(m["q"])`, 1},
		{"named_conversion_back_to_string", `type K string;func drop(m map[any]string,k K){delete(m,string(k))}`, `m:=map[any]string{"q":source()};drop(m,K("q"));sink(m["q"])`, 0},
		{"helper_numeric_wrap_delete", `func drop(m map[int8]string,k int){delete(m,int8(k))}`, `m:=map[int8]string{1:source()};drop(m,257);sink(m[1])`, 0},
		{"helper_numeric_widen_delete", `func drop(m map[any]string,k int8){delete(m,int64(k))}`, `m:=map[any]string{int64(1):source()};drop(m,1);sink(m[int64(1)])`, 0},
		{"helper_numeric_widen_distinct", `func drop(m map[any]string,k int8){delete(m,int64(k))}`, `m:=map[any]string{int8(1):source()};drop(m,1);sink(m[int8(1)])`, 1},
		{"helper_float_round_delete", `func drop(m map[float32]string,k int){delete(m,float32(k))}`, `m:=map[float32]string{16777216:source()};drop(m,16777217);sink(m[16777216])`, 0},
		{"helper_float_fraction_delete_weak", `func drop(m map[int]string,k float64){delete(m,int(k))}`, `m:=map[int]string{2:source()};drop(m,1.9);sink(m[2])`, 1},
		{"helper_float_overflow_delete_weak", `func drop(m map[int8]string,k float64){delete(m,int8(k))}`, `m:=map[int8]string{1:source()};drop(m,257);sink(m[1])`, 1},
		{"float_int_exact_delete", `func drop(m map[int]string,k float64){delete(m,int(k))}`, `m:=map[int]string{1:source()};drop(m,1);sink(m[1])`, 0},
		{"float_nonbinary_same_delete", ``, `m:=map[float64]string{0.1:source()};delete(m,0.1);sink(m[0.1])`, 0},
		{"complex_nonbinary_same_delete", ``, `m:=map[complex64]string{0.1+0.2i:source()};delete(m,0.1+0.2i);sink(m[0.1+0.2i])`, 0},
		{"complex_round_write", `func put(m map[complex64]string,k complex128,v string){m[complex64(k)]=v}`, `m:=map[complex64]string{};put(m,16777217+16777217i,source());sink(m[16777216+16777216i])`, 1},
		{"bool_same_delete", ``, `m:=map[any]string{true:source()};delete(m,true);sink(m[true])`, 0},
		{"bool_named_distinct", `type K bool`, `m:=map[any]string{K(true):source()};delete(m,true);sink(m[K(true)])`, 1},
		{"helper_aggregate_delete_weak", `func drop(m map[[1]int]string,k [1]int){delete(m,k)}`, `k:=[1]int{1};m:=map[[1]int]string{k:source()};drop(m,k);sink(m[k])`, 1},
		{"interface_nan_delete_weak", ``, `z:=0.0;k:=z/z;m:=map[any]string{1.0:source()};delete(m,k);sink(m[1.0])`, 1},
		{"complex_nan_delete_weak", ``, `z:=0.0;k:=complex(z/z,0);m:=map[complex128]string{1:source()};delete(m,k);sink(m[1])`, 1},
		{"array_nan_delete_weak", ``, `z:=0.0;k:=[1]float64{z/z};m:=map[[1]float64]string{{1}:source()};delete(m,k);sink(m[[1]float64{1}])`, 1},
		{"struct_nan_delete_weak", ``, `z:=0.0;k:=struct{f float64}{z/z};m:=map[struct{f float64}]string{{1}:source()};delete(m,k);sink(m[struct{f float64}{1}])`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "package main\nfunc source()string{return \"input\"};func sink(string){};var unknown bool;func flag()bool{return unknown}\n" + tc.helpers + "\nfunc main(){" + tc.body + "}"
			cg, pkg := detailedGraphForSource(t, src)
			got := CheckDetailed(cg, NewSources(pkg+".source"), NewSinks(pkg+".sink"))
			if len(got) != tc.want {
				t.Errorf("diagnostics=%d, want %d", len(got), tc.want)
			}
			if !reflect.DeepEqual(got, CheckDetailed(cg, NewSources(pkg+".source"), NewSinks(pkg+".sink"))) {
				t.Fatal("unstable repeated result")
			}
			for _, d := range got {
				if d.Result.SourceType != pkg+".source" || d.Result.SinkType != pkg+".sink" || !d.Result.ReportPos().IsValid() {
					t.Fatalf("wrong attribution: %+v", d.Result)
				}
				assertEvidenceOrder(t, evidenceKinds(d.Evidence), EvidenceSourceMatch, EvidenceSinkMatch)
			}
		})
	}
}

// A same-key delete is semantically clean, but proving these native-width
// conversions without target sizes would make other key comparisons unsound.
// Baseline constant-text matching reported zero; this is an explicit, newly
// conservative boundary rather than a supported tainted flow.
func TestMapKeyNativeWidthPrecisionBoundary(t *testing.T) {
	for _, typ := range []string{"int", "uint", "uintptr"} {
		t.Run(typ, func(t *testing.T) {
			src := "package main;func source()string{return \"input\"};func sink(string){};func main(){x:=uint64(1)<<40;k:=" + typ + "(x);m:=map[" + typ + "]string{k:source()};delete(m,k);sink(m[k])}"
			cg, pkg := detailedGraphForSource(t, src)
			got := CheckDetailed(cg, NewSources(pkg+".source"), NewSinks(pkg+".sink"))
			if len(got) != 1 {
				t.Fatalf("observed=%d, want conservative 1 (semantic 0, baseline 0)", len(got))
			}
			if !reflect.DeepEqual(got, CheckDetailed(cg, NewSources(pkg+".source"), NewSinks(pkg+".sink"))) {
				t.Fatal("unstable diagnostics/evidence")
			}
			t.Log("new conservative boundary: observed 1; semantic and baseline 0")
		})
	}
}
