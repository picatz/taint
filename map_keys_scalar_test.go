package taint

import (
	"go/constant"
	"go/token"
	"go/types"
	"testing"
)

func TestMapKeyScalarNormalization(t *testing.T) {
	for _, tc := range []struct {
		name, raw, want string
		kind            token.Token
		typ             types.Type
		known           bool
	}{
		{"int8_positive_wrap", "257", "1", token.INT, types.Typ[types.Int8], true},
		{"int8_negative_wrap", "-129", "127", token.INT, types.Typ[types.Int8], true},
		{"int8_min", "128", "-128", token.INT, types.Typ[types.Int8], true},
		{"uint8_negative_wrap", "-1", "255", token.INT, types.Typ[types.Uint8], true},
		{"int64_wrap", "18446744073709551615", "-1", token.INT, types.Typ[types.Int64], true},
		{"uint64_wrap", "18446744073709551616", "0", token.INT, types.Typ[types.Uint64], true},
		{"architecture_int_negative_unknown", "-2147483649", "", token.INT, types.Typ[types.Int], false},
		{"architecture_int_positive_unknown", "2147483648", "", token.INT, types.Typ[types.Int], false},
		{"architecture_uint_negative_unknown", "-1", "", token.INT, types.Typ[types.Uint], false},
		{"architecture_uint_positive_unknown", "4294967296", "", token.INT, types.Typ[types.Uint], false},
		{"architecture_uint_safe", "4294967295", "4294967295", token.INT, types.Typ[types.Uint], true},
		{"float32_round", "16777217", "16777216", token.INT, types.Typ[types.Float32], true},
		{"float64_round", "9007199254740993", "9007199254740992", token.INT, types.Typ[types.Float64], true},
		{"float32_tie_even_high", "16777219", "16777220", token.INT, types.Typ[types.Float32], true},
		{"float32_underflow", "1e-100", "0", token.FLOAT, types.Typ[types.Float32], true},
		{"float32_overflow_unknown", "1e100", "", token.FLOAT, types.Typ[types.Float32], false},
		{"float64_overflow_unknown", "1e1000", "", token.FLOAT, types.Typ[types.Float64], false},
		{"float_to_int_fractional_unknown", "1.5", "", token.FLOAT, types.Typ[types.Int32], false},
		{"float_to_int_overflow_unknown", "256.0", "", token.FLOAT, types.Typ[types.Uint8], false},
		{"float_to_int_exact", "255.0", "255", token.FLOAT, types.Typ[types.Uint8], true},
		{"integer_to_string_unknown", "113", "", token.INT, types.Typ[types.String], false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := constant.MakeFromLiteral(tc.raw, tc.kind, 0)
			if raw.Kind() == constant.Unknown {
				t.Fatalf("invalid literal %q", tc.raw)
			}
			got, ok := scalarMapKeyConstant(raw, tc.typ)
			if ok != tc.known {
				t.Fatalf("known=%v, want %v; key=%#v", ok, tc.known, got)
			}
			if !ok {
				return
			}
			want := constant.MakeFromLiteral(tc.want, token.INT, 0)
			if !types.Identical(got.typ, tc.typ) || !constant.Compare(got.value, token.EQL, want) {
				t.Fatalf("got %s:%s, want %s:%s", got.value, got.typ, want, tc.typ)
			}
		})
	}
}
