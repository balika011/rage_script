#include "rage.hpp"

int idaapi emu(const insn_t &insn)
{
	uint32 Feature = insn.get_canon_feature();
	bool flag1 = is_forced_operand(insn.ea, 0);
	bool flag2 = is_forced_operand(insn.ea, 1);
	bool flag3 = is_forced_operand(insn.ea, 2);

	bool flow = (Feature & CF_STOP) == 0;

	//
	// Determine if the next instruction should be executed
	//
	if (segtype(insn.ea) == SEG_XTRN)
		flow = false;
	if (flow)
		add_cref(insn.ea, insn.ea + insn.size, fl_F);

	return 1;
}

int idaapi is_align_insn(ea_t ea)
{
	insn_t insn;
	decode_insn(&insn, ea);
	switch ( insn.itype )
	{
		default:
			return 0;
	}
	return insn.size;
}
