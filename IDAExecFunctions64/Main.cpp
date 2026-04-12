#include <fstream>
#include <stop_token>
#include <vector>
#include <cstring>

#define __EA64__

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <nalt.hpp>

#include <Format/Format.hpp>
#include <Import/MappingsImporter.hpp>

static void LoadOldMapping(const std::vector<uint8_t>& Buffer, ea_t ImageBase)
{
	size_t Position = 0;
	const size_t Size = Buffer.size();

	while (Position + sizeof(uint32_t) + sizeof(uint16_t) <= Size)
	{
		uint32_t Offset;
		memcpy(&Offset, Buffer.data() + Position, sizeof(Offset));
		Position += sizeof(Offset);

		uint16_t NameLength;
		memcpy(&NameLength, Buffer.data() + Position, sizeof(NameLength));
		Position += sizeof(NameLength);

		if (Position + NameLength > Size)
			break;

		std::string Name(reinterpret_cast<const char*>(Buffer.data() + Position), NameLength);
		Position += NameLength;

		set_name(ImageBase + Offset, Name.c_str(), SN_NOCHECK | SN_NOWARN | SN_FORCE);
	}
}

struct IDAMappingsPlugin : public plugmod_t
{
	bool idaapi run(size_t) override
	{
		char* Path = ask_file(false, "*.*", "Load .idmap (V1) or .usmap (V2) mapping file");
		if (!Path || !Path[0])
			return false;

		std::ifstream File(Path, std::ios::binary | std::ios::ate);
		if (!File)
		{
			msg("[IDAMappingsImporter] Failed to open file!\n");
			return true;
		}

		const auto FileSize = File.tellg();
		std::vector<uint8_t> Buffer(FileSize);
		File.seekg(0);
		File.read(reinterpret_cast<char*>(Buffer.data()), FileSize);

		const ea_t ImageBase = get_imagebase();

		if (!Buffer.empty() && Buffer[0] == MappingLayouts::FileMagic)
		{
			msg("[IDAMappingsImporter] Loading V2 mapping file...\n");
			LoadMappings(std::move(Buffer), ImageBase);
		}
		else
		{
			msg("[IDAMappingsImporter] Loading V1 mapping file...\n");
			LoadOldMapping(Buffer, ImageBase);
		}
		
		msg("[IDAMappingsImporter] Done!\n");
		
		return true;
	}
};

static plugmod_t* idaapi init()
{
	return new IDAMappingsPlugin();
}

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_UNL | PLUGIN_MULTI,
	init,
	nullptr,
	nullptr,
	"Load .idmap/.usmap mapping files",
	"IDA Mappings Importer - Load UE SDK mapping files",
	"IDAMappingsImporteor",
	"Ctrl-Alt-D",
};
