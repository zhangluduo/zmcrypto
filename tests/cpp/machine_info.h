// machine.h: interface for the machine class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_MACHINE_H__9F09D887_6FC2_473A_91B0_0EC626F7AB45__INCLUDED_)
#define AFX_MACHINE_H__9F09D887_6FC2_473A_91B0_0EC626F7AB45__INCLUDED_

#include <string>

std::string get_datetime();
std::string get_os();
std::string get_cpu();
std::string get_memory();
std::string get_compiler();

#endif // !defined(AFX_MACHINE_H__9F09D887_6FC2_473A_91B0_0EC626F7AB45__INCLUDED_)
