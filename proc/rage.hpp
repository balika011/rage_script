#ifndef _RAGE_HPP
#define _RAGE_HPP

#include "idaidp.hpp"
#include "ins.hpp"
#include <diskio.hpp>

enum RegNo
{
	rVcs, rVds,		// virtual registers for code and data segments
};

// I/O port definitions

const ioport_t *find_port(ea_t address);
const char *find_bit(ea_t address, size_t bit);

// memory configuration

int	idaapi ana(insn_t *_insn);
int	idaapi emu(const insn_t &insn);

int	idaapi is_align_insn(ea_t ea);

#endif // _RAGE_HPP
