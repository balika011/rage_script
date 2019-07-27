#include "rage.hpp"
#include <segregs.hpp>
#include <diskio.hpp>
#include <loader.hpp>
#include <fixup.hpp>
#include "notify_codes.hpp"

static const char *const register_names[] =
{
	"cs","ds",			 // virtual registers for code and data segments
};

static asm_t rageasm =
{
	AS_COLON|AS_N2CHR|ASH_HEXF3|ASD_DECF0|ASB_BINF3|ASO_OCTF0|AS_ONEDUP,
	0,
	"RAGE Assembler",
	0,
	NULL,				 // header lines
	".org",			 // org
	".exit",			// end

	";",					// comment string
	'"',					// string delimiter
	'\'',				 // char delimiter
	"\"'",				// special symbols in char and string constants

	".db",				// ascii string directive
	".db",				// byte directive
	".dw",				// word directive
	".dd",				// double words
	NULL,				 // no qwords
	NULL,				 // oword	(16 bytes)
	NULL,				 // float	(4 bytes)
	NULL,				 // double (8 bytes)
	NULL,				 // tbyte	(10/12 bytes)
	NULL,				 // packed decimal real
	NULL,				 // arrays (#h,#d,#v,#s(...)
	".byte %s",	 // uninited arrays
	".equ",			 // equ
	NULL,				 // 'seg' prefix (example: push seg seg001)
	NULL,				 // current IP (instruction pointer)
	NULL,				 // func_header
	NULL,				 // func_footer
	NULL,				 // "public" name keyword
	NULL,				 // "weak"	 name keyword
	NULL,				 // "extrn"	name keyword
	NULL,				 // "comm" (communal variable)
	NULL,				 // get_type_name
	NULL,				 // "align" keyword
	'(', ')',		 // lbrace, rbrace
	NULL,				 // mod
	"&",					// and
	"|",					// or
	"^",					// xor
	"~",					// not
	"<<",				 // shl
	">>",				 // shr
	NULL,				 // sizeof
};

static asm_t *const asms[] = { &rageasm, NULL };


static ssize_t idaapi notify(void *, int msgid, va_list va)
{
#ifdef _DEBUG
	if (msgid == processor_t::ev_extract_address ||
		msgid == processor_t::ev_str2reg ||
		msgid == processor_t::ev_get_bg_color)
		return 0;

	const char* msgstr = "unknown";

	if (msgid == 0) msgstr = "ev_init";
	else if (msgid == 1) msgstr = "ev_term";
	else if (msgid == 2) msgstr = "ev_newprc";
	else if (msgid == 3) msgstr = "ev_newasm";
	else if (msgid == 4) msgstr = "ev_newfile";
	else if (msgid == 5) msgstr = "ev_oldfile";
	else if (msgid == 6) msgstr = "ev_newbinary";
	else if (msgid == 7) msgstr = "ev_endbinary";
	else if (msgid == 8) msgstr = "ev_set_idp_options";
	else if (msgid == 9) msgstr = "ev_set_proc_options";
	else if (msgid == 10) msgstr = "ev_ana_insn";
	else if (msgid == 11) msgstr = "ev_emu_insn";
	else if (msgid == 12) msgstr = "ev_out_header";
	else if (msgid == 13) msgstr = "ev_out_footer";
	else if (msgid == 14) msgstr = "ev_out_segstart";
	else if (msgid == 15) msgstr = "ev_out_segend";
	else if (msgid == 16) msgstr = "ev_out_assumes";
	else if (msgid == 17) msgstr = "ev_out_insn";
	else if (msgid == 18) msgstr = "ev_out_mnem";
	else if (msgid == 19) msgstr = "ev_out_operand";
	else if (msgid == 20) msgstr = "ev_out_data";
	else if (msgid == 21) msgstr = "ev_out_label";
	else if (msgid == 22) msgstr = "ev_out_special_item";
	else if (msgid == 23) msgstr = "ev_gen_stkvar_def";
	else if (msgid == 24) msgstr = "ev_gen_regvar_def";
	else if (msgid == 25) msgstr = "ev_gen_src_file_lnnum";
	else if (msgid == 26) msgstr = "ev_creating_segm";
	else if (msgid == 27) msgstr = "ev_moving_segm";
	else if (msgid == 28) msgstr = "ev_coagulate";
	else if (msgid == 29) msgstr = "ev_undefine";
	else if (msgid == 30) msgstr = "ev_treat_hindering_item";
	else if (msgid == 31) msgstr = "ev_rename";
	else if (msgid == 32) msgstr = "ev_is_far_jump";
	else if (msgid == 33) msgstr = "ev_is_sane_insn";
	else if (msgid == 34) msgstr = "ev_is_cond_insn";
	else if (msgid == 35) msgstr = "ev_is_call_insn";
	else if (msgid == 36) msgstr = "ev_is_ret_insn";
	else if (msgid == 37) msgstr = "ev_may_be_func";
	else if (msgid == 38) msgstr = "ev_is_basic_block_end";
	else if (msgid == 39) msgstr = "ev_is_indirect_jump";
	else if (msgid == 40) msgstr = "ev_is_insn_table_jump";
	else if (msgid == 41) msgstr = "ev_is_switch";
	else if (msgid == 42) msgstr = "ev_calc_switch_cases";
	else if (msgid == 43) msgstr = "ev_create_switch_xrefs";
	else if (msgid == 44) msgstr = "ev_is_align_insn";
	else if (msgid == 45) msgstr = "ev_is_alloca_probe";
	else if (msgid == 46) msgstr = "ev_delay_slot_insn";
	else if (msgid == 47) msgstr = "ev_is_sp_based";
	else if (msgid == 48) msgstr = "ev_can_have_type";
	else if (msgid == 49) msgstr = "ev_cmp_operands";
	else if (msgid == 50) msgstr = "ev_adjust_refinfo";
	else if (msgid == 51) msgstr = "ev_get_operand_string";
	else if (msgid == 52) msgstr = "ev_get_reg_name";
	else if (msgid == 53) msgstr = "ev_str2reg";
	else if (msgid == 54) msgstr = "ev_get_autocmt";
	else if (msgid == 55) msgstr = "ev_get_bg_color";
	else if (msgid == 56) msgstr = "ev_is_jump_func";
	else if (msgid == 57) msgstr = "ev_func_bounds";
	else if (msgid == 58) msgstr = "ev_verify_sp";
	else if (msgid == 59) msgstr = "ev_verify_noreturn";
	else if (msgid == 60) msgstr = "ev_create_func_frame";
	else if (msgid == 61) msgstr = "ev_get_frame_retsize";
	else if (msgid == 62) msgstr = "ev_get_stkvar_scale_factor";
	else if (msgid == 63) msgstr = "ev_demangle_name";
	else if (msgid == 64) msgstr = "ev_add_cref";
	else if (msgid == 65) msgstr = "ev_add_dref";
	else if (msgid == 66) msgstr = "ev_del_cref";
	else if (msgid == 67) msgstr = "ev_del_dref";
	else if (msgid == 68) msgstr = "ev_coagulate_dref";
	else if (msgid == 69) msgstr = "ev_may_show_sreg";
	else if (msgid == 70) msgstr = "ev_loader_elf_machine";
	else if (msgid == 71) msgstr = "ev_auto_queue_empty";
	else if (msgid == 72) msgstr = "ev_validate_flirt_func";
	else if (msgid == 73) msgstr = "ev_adjust_libfunc_ea";
	else if (msgid == 74) msgstr = "ev_assemble";
	else if (msgid == 75) msgstr = "ev_extract_address";
	else if (msgid == 76) msgstr = "ev_realcvt";
	else if (msgid == 77) msgstr = "ev_gen_asm_or_lst";
	else if (msgid == 78) msgstr = "ev_gen_map_file";
	else if (msgid == 79) msgstr = "ev_create_flat_group";
	else if (msgid == 80) msgstr = "ev_getreg";
	else if (msgid == 81) msgstr = "ev_analyze_prolog";
	else if (msgid == 82) msgstr = "ev_calc_spdelta";
	else if (msgid == 83) msgstr = "ev_calcrel";
	else if (msgid == 84) msgstr = "ev_find_reg_value";
	else if (msgid == 85) msgstr = "ev_find_op_value";
	else if (msgid == 86) msgstr = "ev_replaying_undo";
	else if (msgid == 87) msgstr = "ev_ending_undo";
	else if (msgid == 88) msgstr = "ev_last_cb_before_debugger";
	else if (msgid == 1000) msgstr = "ev_next_exec_insn";
	else if (msgid == 1001) msgstr = "ev_calc_step_over";
	else if (msgid == 1002) msgstr = "ev_calc_next_eas";
	else if (msgid == 1003) msgstr = "ev_get_macro_insn_head";
	else if (msgid == 1004) msgstr = "ev_get_dbr_opnum";
	else if (msgid == 1005) msgstr = "ev_insn_reads_tbit";
	else if (msgid == 1006) msgstr = "ev_clean_tbit";
	else if (msgid == 1007) msgstr = "ev_get_idd_opinfo";
	else if (msgid == 1008) msgstr = "ev_get_reg_info";
	else if (msgid == 1009) msgstr = "ev_last_cb_before_type_callbacks";
	else if (msgid == 2000) msgstr = "ev_setup_til";
	else if (msgid == 2001) msgstr = "ev_get_abi_info";
	else if (msgid == 2002) msgstr = "ev_max_ptr_size";
	else if (msgid == 2003) msgstr = "ev_get_default_enum_size";
	else if (msgid == 2004) msgstr = "ev_get_cc_regs";
	else if (msgid == 2005) msgstr = "ev_get_stkarg_offset";
	else if (msgid == 2006) msgstr = "ev_shadow_args_size";
	else if (msgid == 2007) msgstr = "ev_get_simd_types";
	else if (msgid == 2008) msgstr = "ev_calc_cdecl_purged_bytes";
	else if (msgid == 2009) msgstr = "ev_calc_purged_bytes";
	else if (msgid == 2010) msgstr = "ev_calc_retloc";
	else if (msgid == 2011) msgstr = "ev_calc_arglocs";
	else if (msgid == 2012) msgstr = "ev_calc_varglocs";
	else if (msgid == 2013) msgstr = "ev_adjust_argloc";
	else if (msgid == 2014) msgstr = "ev_lower_func_type";
	else if (msgid == 2015) msgstr = "ev_equal_reglocs";
	else if (msgid == 2016) msgstr = "ev_use_stkarg_type";
	else if (msgid == 2017) msgstr = "ev_use_regarg_type";
	else if (msgid == 2018) msgstr = "ev_use_arg_types";
	else if (msgid == 2019) msgstr = "ev_arg_addrs_ready";
	else if (msgid == 2020) msgstr = "ev_decorate_name";
	else if (msgid == 2021) msgstr = "ev_last_cb_before_loader";
	else if (msgid == 3000) msgstr = "ev_loader";
#endif

	switch (msgid)
	{
		case processor_t::ev_ana_insn:
		{
			insn_t *out = va_arg(va, insn_t *);
			return ana(out);
		}

		case processor_t::ev_emu_insn:
		{
			const insn_t *insn = va_arg(va, const insn_t *);
			return emu(*insn) ? 1 : -1;
		}

		case processor_t::ev_out_insn:
		{
			outctx_t *ctx = va_arg(va, outctx_t *);
			out_insn(*ctx);
			return 1;
		}

		case processor_t::ev_out_operand:
		{
			outctx_t *ctx = va_arg(va, outctx_t *);
			const op_t *op = va_arg(va, const op_t *);
			return out_opnd(*ctx, *op) ? 1 : -1;
		}
	}

#ifdef _DEBUG
	msg("notify(%s)\n", msgstr);
#endif
	return 0;
}

static const uchar startcode[] = { 0x2D };
static bytes_t startcodes[] =
{
	{ sizeof(startcode), startcode },
	{ 0, NULL }
};

static const uchar retcode[] = { 0x2E };
static bytes_t retcodes[] =
{
	{ sizeof(retcode), retcode },
	{ 0, NULL }
};

static const char *const shnames[] = { "RAGE", NULL };
static const char *const lnames[] = { "Rockstar Advanced Game Engine", NULL };

processor_t LPH =
{
	IDP_INTERFACE_VERSION,	// version
	0x8000 | 141,			// id
	PRN_HEX | PR_RNAMESOK,	// flag
	PR2_IDP_OPTS,			// the module has processor-specific configuration options
	8,						// 8 bits in a byte for code segments
	8,						// 8 bits in a byte for other segments

	shnames,
	lnames,

	asms,

	notify,

	register_names,			 // Register names
	qnumber(register_names), // Number of registers

	rVcs,								 // first
	rVds,								 // last
	0,										// size of a segment register
	rVcs, rVds,

	startcodes,
	retcodes,

	RAGE_NOP,
	RAGE_last,
	Instructions,				 // instruc
	0,										// int tbyte_size;	-- doesn't exist
	{ 0, },							 // char real_width[4];
						// number of symbols after decimal point
						// 2byte float (0-does not exist)
						// normal float
						// normal double
						// long double
	RAGE_LEAVE,							// Icode of return instruction. It is ok to give any of possible return instructions
};
