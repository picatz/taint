package taint

import (
	"go/constant"
	"go/token"
	"go/types"
	"math"

	"golang.org/x/tools/go/ssa"
)

// A known interface key includes its concrete runtime type. Equal constant
// spellings alone do not make int(1), int64(1), or named integer types equal.
// Aliases, unlike defined types, compare equal through types.Identical.
type mapKeyConstant struct {
	value constant.Value
	typ   types.Type
}

func (a mapKeyConstant) equal(b mapKeyConstant) bool {
	return types.Identical(a.typ, b.typ) && constant.Compare(a.value, token.EQL, b.value)
}

func mapKeysMayMatch(a, b ssa.Value) (bool, bool) {
	return mapKeysMayMatchResolved(a, b, nil)
}

func mapKeysMayMatchResolved(a, b ssa.Value, resolve func(ssa.Value) ssa.Value) (bool, bool) {
	ka, aOK := resolveMapKeyConstant(a, resolve, map[ssa.Value]struct{}{})
	kb, bOK := resolveMapKeyConstant(b, nil, map[ssa.Value]struct{}{})
	if aOK && bOK {
		eq := ka.equal(kb)
		return eq, eq
	}
	// SSA identity is not sufficient: floating-point NaNs, including those
	// inside interfaces, arrays, and structs, are not equal to themselves.
	return true, false
}

func resolveMapKeyConstant(v ssa.Value, resolve func(ssa.Value) ssa.Value, seen map[ssa.Value]struct{}) (mapKeyConstant, bool) {
	if v == nil {
		return mapKeyConstant{}, false
	}
	if _, ok := seen[v]; ok {
		return mapKeyConstant{}, false
	}
	seen[v] = struct{}{}
	if resolve != nil {
		if actual := resolve(v); actual != v {
			return resolveMapKeyConstant(actual, resolve, seen)
		}
	}
	visit := func(value ssa.Value) (mapKeyConstant, bool) {
		return resolveMapKeyConstant(value, resolve, seen)
	}
	switch value := v.(type) {
	case *ssa.Const:
		return scalarMapKeyConstant(value.Value, value.Type())
	case *ssa.MakeInterface:
		return visit(value.X)
	case *ssa.ChangeInterface:
		return visit(value.X)
	case *ssa.ChangeType:
		key, ok := visit(value.X)
		if !ok {
			return mapKeyConstant{}, false
		}
		if _, isInterface := value.Type().Underlying().(*types.Interface); isInterface {
			return key, true
		}
		return scalarMapKeyConstant(key.value, value.Type())
	case *ssa.Convert:
		key, ok := visit(value.X)
		if ok {
			converted, known := scalarMapKeyConstant(key.value, value.Type())
			from, fromBasic := key.typ.Underlying().(*types.Basic)
			to, toBasic := value.Type().Underlying().(*types.Basic)
			// Out-of-range float-to-int conversion is implementation
			// dependent, unlike integer-to-integer truncation.
			if known && fromBasic && toBasic && from.Info()&types.IsFloat != 0 && to.Info()&types.IsInteger != 0 && !constant.Compare(key.value, token.EQL, converted.value) {
				return mapKeyConstant{}, false
			}
			return converted, known
		}
	case *ssa.TypeAssert:
		if !value.CommaOk {
			return assertedMapKeyConstant(value, resolve, seen)
		}
	case *ssa.Extract:
		if assertion, ok := value.Tuple.(*ssa.TypeAssert); ok && value.Index == 0 {
			return assertedMapKeyConstant(assertion, resolve, seen)
		}
	case *ssa.UnOp:
		if value.Op == token.MUL {
			if stored, ok := storedValuesForLoad(value); ok {
				return commonMapKeyConstant(stored, resolve, seen)
			}
		}
	case *ssa.Phi:
		return commonMapKeyConstant(value.Edges, resolve, seen)
	}
	return mapKeyConstant{}, false
}

func assertedMapKeyConstant(assertion *ssa.TypeAssert, resolve func(ssa.Value) ssa.Value, seen map[ssa.Value]struct{}) (mapKeyConstant, bool) {
	key, ok := resolveMapKeyConstant(assertion.X, resolve, seen)
	if !ok {
		return mapKeyConstant{}, false
	}
	if iface, ok := assertion.AssertedType.Underlying().(*types.Interface); ok {
		return key, types.Implements(key.typ, iface)
	}
	return key, types.Identical(key.typ, assertion.AssertedType)
}

func commonMapKeyConstant(values []ssa.Value, resolve func(ssa.Value) ssa.Value, seen map[ssa.Value]struct{}) (mapKeyConstant, bool) {
	var out mapKeyConstant
	for i, value := range values {
		got, ok := resolveMapKeyConstant(value, resolve, cloneSSAValueSeen(seen))
		if !ok || (i > 0 && !out.equal(got)) {
			return mapKeyConstant{}, false
		}
		out = got
	}
	return out, len(values) > 0
}

// SSA can fold a runtime conversion into a Const while retaining its original
// abstract value (emitConv deliberately does not truncate it). Normalize fixed
// width integers and finite floating/complex values before comparing keys.
// Unknown values, fractional float-to-int conversions, integer-to-string
// conversions and architecture-dependent integer narrowing remain conservative.
func scalarMapKeyConstant(value constant.Value, typ types.Type) (mapKeyConstant, bool) {
	if value == nil || typ == nil {
		return mapKeyConstant{}, false
	}
	basic, ok := typ.Underlying().(*types.Basic)
	if !ok {
		return mapKeyConstant{}, false
	}
	switch {
	case basic.Info()&types.IsBoolean != 0:
		if value.Kind() != constant.Bool {
			return mapKeyConstant{}, false
		}
	case basic.Info()&types.IsString != 0:
		if value.Kind() != constant.String {
			return mapKeyConstant{}, false
		}
	case basic.Info()&types.IsInteger != 0:
		original := value
		value = constant.ToInt(value)
		if value.Kind() != constant.Int {
			return mapKeyConstant{}, false
		}
		var bits uint
		switch basic.Kind() {
		case types.Int8, types.Uint8:
			bits = 8
		case types.Int16, types.Uint16:
			bits = 16
		case types.Int32, types.Uint32:
			bits = 32
		case types.Int64, types.Uint64:
			bits = 64
		default:
			// int, uint and uintptr have target-dependent widths. Values
			// representable on every supported width need no truncation.
			if basic.Info()&types.IsUnsigned != 0 {
				if constant.Sign(value) < 0 || constant.BitLen(value) > 32 {
					return mapKeyConstant{}, false
				}
			} else if n, exact := constant.Int64Val(value); !exact || n < math.MinInt32 || n > math.MaxInt32 {
				return mapKeyConstant{}, false
			}
		}
		if bits != 0 {
			// Most keys already fit. Avoid allocating big-integer masks for
			// this identity case; boundary/overflow cases use the same exact
			// truncation below (including the signed minimum).
			fits := constant.BitLen(value) < int(bits)
			if basic.Info()&types.IsUnsigned != 0 {
				fits = constant.Sign(value) >= 0 && constant.BitLen(value) <= int(bits)
			}
			if !fits {
				modulus := constant.Shift(constant.MakeInt64(1), token.SHL, bits)
				mask := constant.BinaryOp(modulus, token.SUB, constant.MakeInt64(1))
				value = constant.BinaryOp(value, token.AND, mask)
				if basic.Info()&types.IsUnsigned == 0 && constant.BitLen(value) == int(bits) {
					value = constant.BinaryOp(value, token.SUB, modulus)
				}
			}
		}
		if original.Kind() != constant.Int && !constant.Compare(original, token.EQL, value) {
			return mapKeyConstant{}, false
		}
	case basic.Info()&types.IsFloat != 0:
		value = finiteMapKeyFloat(value, basic.Kind() == types.Float32)
	case basic.Info()&types.IsComplex != 0:
		value = constant.ToComplex(value)
		if value.Kind() != constant.Complex {
			return mapKeyConstant{}, false
		}
		real := finiteMapKeyFloat(constant.Real(value), basic.Kind() == types.Complex64)
		imag := finiteMapKeyFloat(constant.Imag(value), basic.Kind() == types.Complex64)
		if real == nil || imag == nil {
			return mapKeyConstant{}, false
		}
		value = constant.BinaryOp(real, token.ADD, constant.MakeImag(imag))
	default:
		return mapKeyConstant{}, false
	}
	if value == nil || value.Kind() == constant.Unknown {
		return mapKeyConstant{}, false
	}
	return mapKeyConstant{value: value, typ: typ}, true
}

func finiteMapKeyFloat(value constant.Value, single bool) constant.Value {
	value = constant.ToFloat(value)
	if value.Kind() != constant.Float {
		return nil
	}
	var rounded float64
	if single {
		f, _ := constant.Float32Val(value)
		rounded = float64(f)
	} else {
		rounded, _ = constant.Float64Val(value)
	}
	if math.IsInf(rounded, 0) || math.IsNaN(rounded) {
		return nil
	}
	return constant.MakeFloat64(rounded)
}
