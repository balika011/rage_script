#include <ida.hpp>
#include <loader.hpp>
#include <idp.hpp>
#include <typeinf.hpp>
#include <entry.hpp>
#include <auto.hpp>
#include <diskio.hpp>
#include <vector>

#pragma pack(push, 1)
struct rage_header
{
	uint32_t magic;				// 0x00
	uint32_t version;			// 0x04
	uint64_t pagesOffset;		// 0x08
	uint64_t codePagesOffset;	// 0x10
	uint32_t globalsVersion;	// 0x18
	uint32_t codeSize;			// 0x1C
	uint32_t paramCount;		// 0x20
	uint32_t staticsCount;		// 0x24
	uint32_t globalsCount;		// 0x28
	uint32_t nativesCount;		// 0x2C
	uint64_t staticsOffset;		// 0x30
	uint64_t globalsOffset;		// 0x38
	uint64_t nativesOffset;		// 0x40
	uint64_t zeroes1;			// 0x48
	uint64_t zeroes2;			// 0x50
	uint32_t nameHash;			// 0x58
	uint32_t someNumber2;		// 0x5C
	uint64_t scriptNameOffset;	// 0x60
	uint64_t stringPagesOffset;	// 0x68
	uint32_t stringsSize;		// 0x70
	uint32_t zeroes3;			// 0x74
	uint64_t zeroes4;			// 0x78
};
#pragma pack(pop)

#define RAGE_MAGIC 0x405A9ED0
#define OFFSET_MASK 0x3FFFFFF


int idaapi rage_accept_file(qstring *fileformatname, qstring *processor, linput_t *li, const char *filename)
{
	qlseek(li, 0);

	rage_header header;
	if (qlread(li, &header, sizeof(header)) != sizeof(header))
		return 0;

	if (header.magic != RAGE_MAGIC || header.version != 1)
		return 0;

	*fileformatname = "RAGE script";

	*processor = "RAGE";

	return 1;
}

void createSegment(const char *name, uint32 perms, uchar bitness, uchar type, ea_t start, ea_t size)
{
	//static sel_t g_sel = 1;

	segment_t s;
	memset(&s, 0, sizeof(segment_t));
	s.start_ea = start;
	s.end_ea = s.start_ea + size;
	//s.name
	//s.sclass
	//s.orgbase
	s.align = saAbs;
	s.comb = scCommon; // scPub;
	s.perm = perms;
	s.bitness = bitness;
	//s.flags
	//s.sel = g_sel++;
	//s.defsr
	s.type = type;
	s.color = DEFCOLOR;

	if (!add_segm_ex(&s, name, 0, ADDSEG_SPARSE))
		loader_failure("Could not create segment '%s' at %a..%a", name, s.start_ea, s.end_ea, s.start_ea);
}

void loadOffsetTable(linput_t *li, uint64_t table, uint64_t load_addr, uint32_t size, const char * name, uint32 perms, uchar type)
{
	for (int64_t code_size = size; code_size > 0; code_size -= 0x4000)
	{
		qlseek(li, table);
		uint64_t offset;
		qlread(li, &offset, sizeof(offset));
		offset &= OFFSET_MASK;

		uint32_t size = qmin(code_size, 0x4000);

		msg("code_size: %llx\n", code_size);
		msg("offset: %llx\n", offset);
		msg("size: %llx\n", size);

		createSegment(name, perms, 2, type, load_addr, size);
		file2base(li, offset, load_addr, load_addr + size, FILEREG_PATCHABLE);
		load_addr += 0x4000;
	}
}

void idaapi rage_load_file(linput_t *li, ushort neflags, const char *fileformatname)
{
#ifdef _DEBUG
	debug = IDA_DEBUG_ALWAYS;
#endif

	qlseek(li, 0);

	rage_header header;
	if (qlread(li, &header, sizeof(header)) != sizeof(header))
		loader_failure("Failed to read file header!");

	header.codePagesOffset &= OFFSET_MASK;
	header.staticsOffset &= OFFSET_MASK;
	header.globalsOffset &= OFFSET_MASK;
	header.nativesOffset &= OFFSET_MASK;
	header.stringPagesOffset &= OFFSET_MASK;

	set_processor_type("RAGE", SETPROC_LOADER);

	loadOffsetTable(li, header.codePagesOffset, 0, header.codeSize, "code", SEGPERM_READ | SEGPERM_EXEC, SEG_CODE);

	if (header.staticsCount)
	{
		createSegment("static", SEGPERM_READ | SEGPERM_WRITE, 2, SEG_DATA, 0x1000000000000000, header.staticsCount * 8);
		file2base(li, header.staticsOffset, 0x1000000000000000, 0x1000000000000000 + header.staticsCount * 8, FILEREG_PATCHABLE);
	}
	if (header.globalsCount)
		loader_failure("Please add global support now!");
	/*{
		createSegment("global", SEGPERM_READ | SEGPERM_WRITE, 2, SEG_DATA, header.globalsOffset, header.globalsCount * 8);
		file2base(li, header.globalsOffset, header.globalsOffset, header.globalsOffset + header.globalsCount * 8, FILEREG_PATCHABLE);
	}*/
	
	if (header.nativesCount)
	{
		createSegment("native", SEGPERM_READ | SEGPERM_WRITE, 2, SEG_XTRN, 0x2000000000000000, header.nativesCount * 8);
		file2base(li, header.nativesOffset, 0x2000000000000000, 0x2000000000000000 + header.nativesCount * 8, FILEREG_PATCHABLE);
	}

	if (header.stringsSize)
		loadOffsetTable(li, header.stringPagesOffset, 0x3000000000000000, header.stringsSize, "string", SEGPERM_READ | SEGPERM_WRITE, SEG_DATA);

#ifdef _DEBUG
	debug = 0;
#endif
}

int idaapi rage_save_file(FILE *fp, const char *fileformatname)
{
	return 0;
}

extern "C" __declspec(dllexport) loader_t LDSC = {
	IDP_INTERFACE_VERSION,
	0,
	rage_accept_file,
	rage_load_file,
	rage_save_file,
	nullptr,
	nullptr
};