#include "rage.hpp"

class out_rage_t : public outctx_t
{
	out_rage_t(void) : outctx_t(BADADDR) {} // not used
public:
	void out_bad_address(ea_t addr);

	bool out_operand(const op_t &x);
	void out_insn(void);
};
CASSERT(sizeof(out_rage_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_rage_t)

void out_rage_t::out_bad_address(ea_t addr)
{
	out_tagon(COLOR_ERROR);
	out_btoa(addr, 16);
	out_tagoff(COLOR_ERROR);
	remember_problem(PR_NONAME, insn.ea);
}

bool out_rage_t::out_operand(const op_t &x)
{
	switch (x.type)
	{
	case o_void:
		return 0;

	case o_imm:
	{
		out_symbol('#');

		int flags = OOFW_IMM;

		switch (insn.itype)
		{
		case RAGE_PUSH_CONST_S16:
			flags |= OOF_SIGNED;
			break;
		}

		out_value(x, flags);
		break;
	}

	case o_near:
	{
		ea_t ea = insn.ea + insn.size + x.addr;
		if (!out_name_expr(x, ea, x.addr))
			out_bad_address(x.addr);
		break;
	}

	case o_far:
	{
		ea_t ea = to_ea(insn.cs, x.addr);
		if (!out_name_expr(x, ea, x.addr))
			out_bad_address(x.addr);
		break;
	}

	case o_mem:
	{
		ea_t ea = map_data_ea(insn, x);
		if (!out_name_expr(x, ea, x.addr))
			out_bad_address(x.addr);
	}
	break;

	default:
		warning("out: %a: bad optype %d", insn.ea, x.type);
	}

	return 1;
}

void out_rage_t::out_insn(void)
{
	out_mnemonic();

	out_one_operand(0);
	if (insn.Op2.type != o_void)
	{
		out_symbol(',');
		out_char(' ');
		out_one_operand(1);
	}
	if (insn.Op3.type != o_void)
	{
		out_symbol(',');
		out_char(' ');
		out_one_operand(2);
	}

	out_immchar_cmts();
	flush_outbuf();
}
