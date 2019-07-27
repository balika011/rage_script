#include "rage.hpp"
#include <fixup.hpp>

int idaapi ana(insn_t *_insn)
{
	if ( _insn == NULL )
		return 0;
	insn_t &insn = *_insn;

	int code = insn.get_next_byte();

	insn.itype = code;
	insn.Op1.type = insn.Op2.type = o_void;

	switch (code)
	{
		case RAGE_NOP:
		case RAGE_IADD:
		case RAGE_ISUB:
		case RAGE_IMUL:
		case RAGE_IDIV:
		case RAGE_IMOD:
		case RAGE_INOT:
		case RAGE_INEG:
		case RAGE_IEQ:
		case RAGE_INE:
		case RAGE_IGT:
		case RAGE_IGE:
		case RAGE_ILT:
		case RAGE_ILE:
		case RAGE_FADD:
		case RAGE_FSUB:
		case RAGE_FMUL:
		case RAGE_FDIV:
		case RAGE_FMOD:
		case RAGE_FNEG:
		case RAGE_FEQ:
		case RAGE_FNE:
		case RAGE_FGT:
		case RAGE_FGE:
		case RAGE_FLT:
		case RAGE_FLE:
			break;
		case RAGE_VADD:
		case RAGE_VSUB:
		case RAGE_VMUL:
		case RAGE_VDIV:
		case RAGE_VNEG:
			return 0;
		case RAGE_IAND:
		case RAGE_IOR:
			break;
		case RAGE_IXOR:
		case RAGE_I2F:
		case RAGE_F2I:
		case RAGE_F2V:
			return 0;

		case RAGE_PUSH_CONST_U8:
			insn.Op1.type = o_imm;
			insn.Op1.value = insn.get_next_byte();
			insn.Op1.dtype = dt_byte;
			break;
		case RAGE_PUSH_CONST_U8_U8:
			insn.Op1.type = o_imm;
			insn.Op1.value = insn.get_next_byte();
			insn.Op1.dtype = dt_byte;
			insn.Op2.type = o_imm;
			insn.Op2.value = insn.get_next_byte();
			insn.Op2.dtype = dt_byte;
			break;
		case RAGE_PUSH_CONST_U8_U8_U8:
			insn.Op1.type = o_imm;
			insn.Op1.value = insn.get_next_byte();
			insn.Op1.dtype = dt_byte;
			insn.Op2.type = o_imm;
			insn.Op2.value = insn.get_next_byte();
			insn.Op2.dtype = dt_byte;
			insn.Op3.type = o_imm;
			insn.Op3.value = insn.get_next_byte();
			insn.Op3.dtype = dt_byte;
			break;
		case RAGE_PUSH_CONST_U32:
			insn.Op1.type = o_imm;
			insn.Op1.value = insn.get_next_dword();
			insn.Op1.dtype = dt_dword;
			break;
		case RAGE_PUSH_CONST_F:
		{
			uint32_t value = insn.get_next_dword();

			insn.Op1.type = o_imm;
			insn.Op1.value = *(float*)&value;
			insn.Op1.dtype = dt_float;
			break;
		}
		case RAGE_DUP:
		case RAGE_DROP:
			break;
		case RAGE_NATIVE:
			insn.Op1.type = o_imm;
			insn.Op1.value = insn.get_next_byte();
			insn.Op1.dtype = dt_byte;
			insn.Op2.type = o_imm;
			insn.Op2.value = insn.get_next_byte();
			insn.Op2.dtype = dt_byte;
			insn.Op3.type = o_imm;
			insn.Op3.value = insn.get_next_byte();
			insn.Op3.dtype = dt_byte;
			break;

		case RAGE_ENTER:
			insn.Op1.type = o_imm;
			insn.Op1.value = insn.get_next_dword();
			insn.Op1.dtype = dt_dword;
			break;
		case RAGE_LEAVE:
			insn.Op1.type = o_imm;
			insn.Op1.value = insn.get_next_word();
			insn.Op1.dtype = dt_word;
			break;

		case RAGE_LOAD:
		case RAGE_STORE:
		case RAGE_STORE_REV:
			return 0;
		case RAGE_LOAD_N:
		case RAGE_STORE_N:
			break;

		case RAGE_ARRAY_U8:
		case RAGE_ARRAY_U8_LOAD:
		case RAGE_ARRAY_U8_STORE:
		case RAGE_LOCAL_U8:
		case RAGE_LOCAL_U8_LOAD:
		case RAGE_LOCAL_U8_STORE:
			insn.Op1.type = o_imm;
			insn.Op1.value = insn.get_next_byte();
			insn.Op1.dtype = dt_byte;
			break;

		case RAGE_STATIC_U8:
		case RAGE_STATIC_U8_LOAD:
		case RAGE_STATIC_U8_STORE:
			insn.Op1.type = o_mem;
			insn.Op1.addr = 0x1000000000000000 + insn.get_next_byte() * 8;
			insn.Op1.dtype = dt_qword;
			break;

		case RAGE_IADD_U8:
		case RAGE_IMUL_U8:
			insn.Op1.type = o_imm;
			insn.Op1.value = insn.get_next_byte();
			insn.Op1.dtype = dt_byte;
			break;
		case RAGE_IOFFSET:
			return 0;
		case RAGE_IOFFSET_U8:
		case RAGE_IOFFSET_U8_LOAD:
		case RAGE_IOFFSET_U8_STORE:
			insn.Op1.type = o_imm;
			insn.Op1.value = insn.get_next_byte();
			insn.Op1.dtype = dt_byte;
			break;
		case RAGE_PUSH_CONST_S16:
			insn.Op1.type = o_imm;
			insn.Op1.value = insn.get_next_word();
			insn.Op1.dtype = dt_word;
			break;
		case RAGE_IADD_S16:
		case RAGE_IMUL_S16:
			return 0;
		case RAGE_IOFFSET_S16:
		case RAGE_IOFFSET_S16_LOAD:
		case RAGE_IOFFSET_S16_STORE:
		case RAGE_ARRAY_U16:
		case RAGE_ARRAY_U16_LOAD:
		case RAGE_ARRAY_U16_STORE:
		case RAGE_LOCAL_U16:
		case RAGE_LOCAL_U16_LOAD:
		case RAGE_LOCAL_U16_STORE:
		case RAGE_STATIC_U16:
		case RAGE_STATIC_U16_LOAD:
		case RAGE_STATIC_U16_STORE:
		case RAGE_GLOBAL_U16:
		case RAGE_GLOBAL_U16_LOAD:
		case RAGE_GLOBAL_U16_STORE:
			insn.Op1.type = o_imm;
			insn.Op1.value = insn.get_next_word();
			insn.Op1.dtype = dt_word;
			break;
		case RAGE_J:
		case RAGE_JZ:
		case RAGE_IEQ_JZ:
		case RAGE_INE_JZ:
		case RAGE_IGT_JZ:
		case RAGE_IGE_JZ:
		case RAGE_ILT_JZ:
		case RAGE_ILE_JZ:
			insn.Op1.type = o_near;
			insn.Op1.addr = (int16_t)insn.get_next_word();
			break;
		case RAGE_CALL:
			insn.Op1.type = o_far;
			insn.Op1.addr = insn.get_next_byte() | (insn.get_next_byte() << 8) | (insn.get_next_byte() << 16);
			break;
		case RAGE_GLOBAL_U24:
		case RAGE_GLOBAL_U24_LOAD:
		case RAGE_GLOBAL_U24_STORE:
			insn.Op1.type = o_imm;
			insn.Op1.value = insn.get_next_byte() | (insn.get_next_byte() << 8) | (insn.get_next_byte() << 16);
			insn.Op1.dtype = dt_dword;
			break;
		case RAGE_PUSH_CONST_U24:
			return 0;
		case RAGE_SWITCH:
			insn.Op1.type = o_imm;
			insn.Op1.value = insn.get_next_byte();
			insn.Op1.dtype = dt_byte;
			break;
		case RAGE_STRING:
			break;
		case RAGE_STRINGHASH:
			return 0;
		case RAGE_TEXT_LABEL_ASSIGN_STRING:
			insn.Op1.type = o_imm;
			insn.Op1.value = insn.get_next_byte();
			insn.Op1.dtype = dt_byte;
			break;
		case RAGE_TEXT_LABEL_ASSIGN_INT:
			return 0;
		case RAGE_TEXT_LABEL_APPEND_STRING:
		case RAGE_TEXT_LABEL_APPEND_INT:
			insn.Op1.type = o_imm;
			insn.Op1.value = insn.get_next_byte();
			insn.Op1.dtype = dt_byte;
			break;
		case RAGE_TEXT_LABEL_COPY:
			break;
		case RAGE_CATCH:
		case RAGE_THROW:
		case RAGE_CALLINDIRECT:
			return 0;

		case RAGE_PUSH_CONST_M1:
			insn.Op1.type = o_imm;
			insn.Op1.value = -1;
			insn.Op1.dtype = dt_byte;
			break;
		case RAGE_PUSH_CONST_0:
			insn.Op1.type = o_imm;
			insn.Op1.value = 0;
			insn.Op1.dtype = dt_byte;
			break;
		case RAGE_PUSH_CONST_1:
			insn.Op1.type = o_imm;
			insn.Op1.value = 1;
			insn.Op1.dtype = dt_byte;
			break;
		case RAGE_PUSH_CONST_2:
			insn.Op1.type = o_imm;
			insn.Op1.value = 2;
			insn.Op1.dtype = dt_byte;
			break;
		case RAGE_PUSH_CONST_3:
			insn.Op1.type = o_imm;
			insn.Op1.value = 3;
			insn.Op1.dtype = dt_byte;
			break;
		case RAGE_PUSH_CONST_4:
			insn.Op1.type = o_imm;
			insn.Op1.value = 4;
			insn.Op1.dtype = dt_byte;
			break;
		case RAGE_PUSH_CONST_5:
			insn.Op1.type = o_imm;
			insn.Op1.value = 5;
			insn.Op1.dtype = dt_byte;
			break;
		case RAGE_PUSH_CONST_6:
			insn.Op1.type = o_imm;
			insn.Op1.value = 6;
			insn.Op1.dtype = dt_byte;
			break;
		case RAGE_PUSH_CONST_7:
			insn.Op1.type = o_imm;
			insn.Op1.value = 7;
			insn.Op1.dtype = dt_byte;
			break;
		case RAGE_PUSH_CONST_FM1:
			insn.Op1.type = o_imm;
			insn.Op1.value = -1.0f;
			insn.Op1.dtype = dt_byte;
			break;
		case RAGE_PUSH_CONST_F0:
			insn.Op1.type = o_imm;
			insn.Op1.value = 0.0f;
			insn.Op1.dtype = dt_byte;
			break;
		case RAGE_PUSH_CONST_F1:
			insn.Op1.type = o_imm;
			insn.Op1.value = 1.0f;
			insn.Op1.dtype = dt_byte;
			break;
		case RAGE_PUSH_CONST_F2:
			insn.Op1.type = o_imm;
			insn.Op1.value = 2.0f;
			insn.Op1.dtype = dt_byte;
			break;
		case RAGE_PUSH_CONST_F3:
			insn.Op1.type = o_imm;
			insn.Op1.value = 3.0f;
			insn.Op1.dtype = dt_byte;
			break;
		case RAGE_PUSH_CONST_F4:
			insn.Op1.type = o_imm;
			insn.Op1.value = 4.0f;
			insn.Op1.dtype = dt_byte;
			break;
		case RAGE_PUSH_CONST_F5:
			insn.Op1.type = o_imm;
			insn.Op1.value = 5.0f;
			insn.Op1.dtype = dt_byte;
			break;
		case RAGE_PUSH_CONST_F6:
			insn.Op1.type = o_imm;
			insn.Op1.value = 6.0f;
			insn.Op1.dtype = dt_byte;
			break;
		case RAGE_PUSH_CONST_F7:
			insn.Op1.type = o_imm;
			insn.Op1.value = 7.0f;
			insn.Op1.dtype = dt_byte;
			break;

		default:
			return 0;
	}

	return insn.size;
}
