package cipher

import (
	"fmt"
	impl "github.com/Rsplwe/ESurfingDialer/internal/cipher/impl"
)

// GetInstance returns a cipher implementation based on algorithm type
func GetInstance(algoType string) (CipherInterface, error) {
	switch algoType {
	case "CAFBCBAD-B6E7-4CAB-8A67-14D39F00CE1E":
		return impl.NewAESCBC(Key1_CAFBCBAD, Key2_CAFBCBAD, IV_CAFBCBAD), nil
	case "A474B1C2-3DE0-4EA2-8C5F-7093409CE6C4":
		return impl.NewAESECB(Key1_A474B1C2, Key2_A474B1C2), nil
	case "5BFBA864-BBA9-42DB-8EAD-49B5F412BD81":
		return impl.NewDESedeCBC(Key1_5BFBA864, Key2_5BFBA864, IV_5BFBA864), nil
	case "6E0B65FF-0B5B-459C-8FCE-EC7F2BEA9FF5":
		return impl.NewDESedeECB(Key1_6E0B65FF, Key2_6E0B65FF), nil
	case "B809531F-0007-4B5B-923B-4BD560398113":
		return impl.NewZUC(Key_B809531F, IV_B809531F), nil
	case "F3974434-C0DD-4C20-9E87-DDB6814A1C48":
		return impl.NewSM4CBC(Key_F3974434, IV_F3974434), nil
	case "ED382482-F72C-4C41-A76D-28EEA0F1F2AF":
		return impl.NewSM4ECB(Key_ED382482), nil
	case "B3047D4E-67DF-4864-A6A5-DF9B9E525C79":
		return impl.NewModXTEA(Key1_B3047D4E, Key2_B3047D4E, Key3_B3047D4E), nil
	case "C32C68F9-CA81-4260-A329-BBAFD1A9CCD1":
		return impl.NewModXTEAIV(Key1_C32C68F9, Key2_C32C68F9, Key3_C32C68F9, IV_C32C68F9), nil
	default:
		return nil, fmt.Errorf("unknown algorithm: %s", algoType)
	}
}
