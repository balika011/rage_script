#ifndef __RAGE_NOTIFY_CODES_HPP
#define __RAGE_NOTIFY_CODES_HPP

#include <idp.hpp>

//----------------------------------------------------------------------
// The following events are supported by the RAGE module in the ph.notify() function
namespace rage_module_t
{
	enum event_codes_t
	{
		ev_set_machine_type = processor_t::ev_loader, // elf-loader 'set machine type' and file type
	};

	inline processor_t::event_t idp_ev(event_codes_t ev)
	{
		return processor_t::event_t(ev);
	}

	inline void set_machine_type(int subarch, bool image_file)
	{
		ph.notify(idp_ev(ev_set_machine_type), subarch, image_file);
	}
}

#endif // __RAGE_NOTIFY_CODES_HPP
