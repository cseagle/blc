/*
   Source for blc IdaPro plugin
   Copyright (c) 2019 Chris Eagle
   Copyright (c) 2020 Alexander Pick

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the Free
   Software Foundation; either version 2 of the License, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
   FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
   more details.

   You should have received a copy of the GNU General Public License along with
   this program; if not, write to the Free Software Foundation, Inc., 59 Temple
   Place, Suite 330, Boston, MA 02111-1307 USA

   Changelog:
   ----------

   Changes by Alexander Pick (alx@pwn.su)

   2020-04-24	- fixed something in the externs recognition for iOS and other (XTRN)
				- string recognition
   2020-04-27	- added new comment functionality
   2020-04-28	- IDA 7.5 compatibility

*/

#ifndef USE_DANGEROUS_FUNCTIONS
#define USE_DANGEROUS_FUNCTIONS 1
#endif  // USE_DANGEROUS_FUNCTIONS

#ifndef USE_STANDARD_FILE_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
#endif

#ifndef NO_OBSOLETE_FUNCS
#define NO_OBSOLETE_FUNCS
#endif

#define __DEFINE_PH__ 1

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <netnode.hpp>
#include <typeinf.hpp>
#include <struct.hpp>
#include <range.hpp>
#include <frame.hpp>
#include <segment.hpp>
#include <funcs.hpp>
#include <search.hpp>
#include <diskio.hpp>
#include <segregs.hpp>
#include <xref.hpp>
#include <help.h>
#include <moves.hpp>
#include <offset.hpp>

#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <map>
#include <set>

#include "plugin.hh"
#include "ast.hh"

#if defined(__NT__)                   // MS Windows
#define DIRSEP "\\"
#else
#define DIRSEP "/"
#endif

// debug flags
//#define DEBUG_PLUGIN 1
//#define DEVFUNC 1

// enable support for additional procs:
// NEC850/RH850 - changed as NSA releases a own module in 9.2 valled V850 vs. v850 (previously)

#define NEWPROCS 1

#ifdef DEBUG_PLUGIN
#define dmsg(x, ...) msg(x, __VA_ARGS__)
#else
#define dmsg(x, ...)
#endif

using std::iostream;
using std::ifstream;
using std::istreambuf_iterator;
using std::map;
using std::set;

//prefix for netnode nodes
#define NETNODEPRE "$ blc_"

struct LocalVar {
	string ghidra_name;
	string current_name;  //current display name in disassembly display
	ea_t offset;      //offset into stack frame if stack var (BADADDR otherwise)

	LocalVar(const string& gname, const string& iname, ea_t _offset = BADADDR) :
		ghidra_name(gname), current_name(iname), offset(_offset) {};
};

struct Decompiled {
	Function* ast;
	func_t* ida_func;
	strvec_t* sv;       //text of the decompiled function displayed in a custom_viewer
	map<string, LocalVar*> locals;

   Decompiled(Function *f, func_t *func) : ast(f), ida_func(func), sv(NULL) {};
   ~Decompiled();

   void set_ud(strvec_t *ud);
   strvec_t *get_ud() {return sv;};
};

Decompiled::~Decompiled() {
	delete ast;
	for (map<string, LocalVar*>::iterator i = locals.begin(); i != locals.end(); i++) {
		delete i->second;
	}
	delete sv;
}

void Decompiled::set_ud(strvec_t* ud) {
	delete sv;
	sv = ud;
}

void decompile_at(ea_t ea, TWidget* w = NULL);
int do_ida_rename(qstring& name, ea_t func);

static map<string, uint32_t> type_sizes;
static map<TWidget*, qvector<ea_t> > histories;
static map<TWidget*, string> views;
static map<TWidget*, Decompiled*> function_map;
static set<string> titles;

arch_map_t arch_map;

string sleigh_id;

static string get_available_title() {
	string title("A");
	while (titles.find(title) != titles.end()) {
		int i = 0;
		while (true) {
			title[i] += 1;
			if (title[i] > 'Z') {
				title[i] = 'A';
				if (title.length() == i) {
					title.push_back('A');
					break;
				}
				else {
					i++;
				}
			}
			else {
				break;
			}
		}
	}
	return title;
}

//---------------------------------------------------------------------------
// get the word under the (keyboard or mouse) cursor
static bool get_current_word(TWidget* v, bool mouse, qstring& word, qstring* line) {
	// query the cursor position
	int x, y;
	if (get_custom_viewer_place(v, mouse, &x, &y) == NULL) {
		dmsg("get_current_word: !get_custom_viewer_place()\n");
		return false;
	}
	// query the line at the cursor
	tag_remove(line, get_custom_viewer_curline(v, mouse));
	if (x >= line->length()) {
		dmsg("get_current_word: x >= line->length()\n");
		return false;
	}
	char* ptr = line->begin() + x;
	
	char* end = ptr;
	char* next = ptr;
	char* last = ptr;

	// find the end of the word
	while (
			(qisalnum(*end) || *end == '_' || 
			(*end == ':' && (
				(*next) == ':') || ((*last) == ':')
			)
		) // added :: as part of the words for std:: etc. names
		&& *end != '\0') { 
		last = end;
		end++;
		next = end + 1;
	}

	if (end == ptr) {
		dmsg("get_current_word: end == ptr\n");
		return false;
	}

	// find the beginning of the word
	while (ptr > line->begin() && (qisalnum(ptr[-1]) || ptr[-1] == '_' || *end == ':')) {
		ptr--;
	}
	if (!qisalpha(*ptr) && *ptr != '_') {
		dmsg("get_current_word: starts with a digit or something else\n");
	//	return false;
	}
	word = qstring(ptr, end - ptr);
	
	dmsg("get_current_word: %s\n", word.c_str());

	return true;
}

static bool navigate_to_word(TWidget* w, bool cursor) {

	qstring word;

	qstring line;

	if (get_current_word(w, cursor, word, &line)) {

		ea_t ea = get_name_ea(BADADDR, word.c_str());

		if (ea != BADADDR) {

			if (is_function_start(ea) && !is_extern_addr(ea)) {

				map<TWidget*, qvector<ea_t> >::iterator mi = histories.find(w);

				if (mi == histories.end() || mi->second.size() == 0 || mi->second.back() != ea) {
					histories[w].push_back(ea);
					decompile_at(ea, w);
				}

			}
			else {

				jumpto(ea);

			}
			return true;
		}
	}
	return false;
}

static void refresh_widget(TWidget* w) {

	Decompiled* dec = function_map[w];

	qstring nodename = NETNODEPRE;

	string nodeappend = std::to_string((long)dec->ida_func->start_ea);

	nodename.append(nodeappend.c_str());

	netnode cno(nodename.c_str());

	vector<string> code;

	dec->ast->print(&code);

	strvec_t* sv = new strvec_t();

	int ci = 0; // lines start at 0 in IDA

	for (vector<string>::iterator si = code.begin(); si != code.end(); si++) {

		qstring pline = si->c_str();

		if (cno != BADNODE) {

			// get length of entry
			int len = cno.supstr(ci, NULL, 0);

			if (len > 1) {

				//msg("length %i \n",len);

				//allocate a buffer of sufficient size
				char* outstr = new char[len];

				// get the comment at the current line number in iteration from superval
				cno.supval(ci, outstr, len);

				// append it as comment
				pline.append(" // ");
				pline.append(outstr);


			}

			sv->push_back(simpleline_t(pline));

		}
		else {

			sv->push_back(simpleline_t(pline));

		}

		ci++;
	}

	callui(ui_custom_viewer_set_userdata, w, sv);

	refresh_custom_viewer(w);

	repaint_custom_viewer(w);

	dec->set_ud(sv);

}

//get the line number in the current custom viewer
int get_custom_viewer_line_number(TWidget* w, int* x, int* y) {

	place_t* pl = get_custom_viewer_place(w, false, x, y);
	tcc_place_type_t pt = get_viewer_place_type(w);

	if (pl && pt == TCCPT_SIMPLELINE_PLACE) {

		simpleline_place_t* slp = (simpleline_place_t*)pl;

		return slp->n;

	}
	else {
		msg("Couldn't retrieve line number\n");
		return false;
	}
}

//---------------------------------------------------------------------------
// Keyboard callback
static bool idaapi ct_keyboard(TWidget* w, int key, int shift, void* ud) {

	ea_t addr = 0;

	if (shift == 0) {

		strvec_t* sv = (strvec_t*)ud;

		switch (key) {

#if DEVFUNC
			//Refresh decompile
		case 0x52: { //R - If I define it as R it won't work for some reason...

			Decompiled* dec = function_map[w];

			func_t* f = dec->ida_func;

			if (f) {

				msg("Re-Decompiled function at 0x%x.\n", f->start_ea);

				decompile_at(f->start_ea, w);

				refresh_widget(w);
			}

			return true;

		}
#endif
				 // Open XRefs Window for focused function
		case 'X': {
			//view xrefs to function
			qstring word;
			qstring line;

			if (get_current_word(w, false, word, &line)) {

				qstring mname(word);

				ea_t name_ea = get_name_ea(BADADDR, word.c_str());

				if (name_ea == BADADDR) {
					//somehow the original name is invalid
					dmsg("xref: %s has no addr\n", word.c_str());
					return -1;
				}

				open_xrefs_window(name_ea);

				return true;
			}
			return true;
		}
				// Jump to address 	
		case 'G':
			if (ask_addr(&addr, "Jump address")) {
				func_t* f = get_func(addr);
				if (f) {
					decompile_at(f->start_ea, w);
				}
			}
			return true;
			// rename the thing under the cursor
		case 'N': {
			Decompiled* dec = function_map[w];
			qstring word;
			qstring line;
			bool refresh = false;
			if (get_current_word(w, false, word, &line)) {
				string sword(word.c_str());
				dmsg("Try to rename: %s\n", word.c_str());
				if (!is_reserved(sword)) { // can't rename a reserved word
					qstring new_name(word);
					map<string, LocalVar*>::iterator mi = dec->locals.find(sword);
					if (mi != dec->locals.end()) {
						dmsg("%s is a local\n", word.c_str());
						LocalVar* lv = mi->second;
						if (ask_str(&word, HIST_IDENT, "Please enter item name") && sword != word.c_str()) {
							string newname(word.c_str());
							//need to make sure new name will be legal
							if (is_reserved(newname) || dec->locals.find(newname) != dec->locals.end() ||
								get_name_ea(BADADDR, newname.c_str()) != BADADDR) {
								msg("rename: \"newname\" is not a valid new name\n");
								return true;
							}
							if (lv->offset != BADADDR) { //stack var
								dmsg("renaming a stack var %s to %s\n", sword.c_str(), word.c_str());
								if (set_member_name(get_frame(dec->ida_func), lv->offset, word.c_str())) {
									lv->current_name = newname;
									dec->locals.erase(sword);
									dec->locals[newname] = lv;
									dec->ast->rename(sword, newname);
									refresh = true;
								}
								else {
									dmsg("set_member_name failed\n");
								}
							}
							else { //not stack var, reg var??
								qstring iname;
								netnode nn(dec->ida_func->start_ea);
								dmsg("renaming a reg var %s to %s\n", sword.c_str(), word.c_str());
								lv->current_name = newname;
								dec->locals.erase(sword);
								dec->locals[word.c_str()] = lv;
								dec->ast->rename(sword, word.c_str());
								nn.hashset(lv->ghidra_name.c_str(), word.c_str());
								refresh = true;
							}
						}
					}
					else {
						// has an own ask dialog
						int res = do_ida_rename(new_name, dec->ida_func->start_ea);

						if (res == 2) {
							//renming a global
							string snew_name(new_name.c_str());
							dec->ast->rename(sword, snew_name);
							dmsg("rename: %s -> %s\n", word.c_str(), new_name.c_str());
							refresh = true;
						}
						else {
							dmsg("rename: bad return code, res = %i\n", res);
						}


					}
				}
				
				else {
				
				}
			}
			if (refresh) {

				Decompiled* dec = function_map[w];

				func_t* f = dec->ida_func;

				decompile_at(f->start_ea, w);

				refresh_widget(w);

				dmsg("Refresh done\n");

			}
			return true;
		}
				//Set type for the thing under the cursor
		case 'Y': {
			Decompiled* dec = function_map[w];  //the ast for the function we are editing
			qstring word;
			qstring line;
			if (get_current_word(w, false, word, &line)) {
				//need to determine the thing being typed along with it's old type
				//user may have selected the type name at a variable's declaration,
				//or the user may have selected the variable name at its declaration
				//or some place it is used, so we need to find the variable's declaration
				//node in the ast (unless it's a global) so that we can change the Type
				//node within the declaration node.

				int x = -1;
				int y = -1;

				y = get_custom_viewer_line_number(w, &x, &y);

				//indent doesn't get factored into ast x/y data
				for (const char* cptr = line.c_str(); *cptr == ' '; cptr++) {
					x--;
				}

				string sword(word.c_str());
				map<string, LocalVar*>::iterator mi = dec->locals.find(sword);
				VarDecl* decl = NULL;
				if (mi != dec->locals.end()) {
					dmsg("Find decl by name (%s)\n", sword.c_str());
					decl = find_decl(dec->ast, sword);
				}
				else {
					dmsg("Find decl by x,y (%d,%d)\n", x, y);
					decl = find_decl(dec->ast, x, y);
				}
				if (decl == NULL) {
					//last chance - see if word refers to a global, then ask IDA its type
				}
				else {
					// msg("You seem to be referring to this decl: %s on line %d col %d\n", decl->var->name.c_str(), decl->line_begin, decl->col_start);
				}
#if 0
//not ready yet
               //need to get string representation of the decl (if type is known) to display to user
               if (ask_str(&word, HIST_IDENT, "Please enter the type declaration")) {
                  //now we need to parse what the user entered to extract only type related info
                  //then determine whether the user entered a type known to ida, and if so
                  //update the ast to change the variable's type. If the variable is a stack variable,
                  //global variable, or function parameter, also change the type in IDA.
                  //If the type is for a register variable, then update the variable's type in a
                  //netnode (like the variable name map)

                  //use parse_decl to parse user text into a type
                  //then will need to extract IDA's tinfo_t information back to an updated ast Type node
               }
#endif
			}
			return true;
		}
				// write a comment
		case IK_DIVIDE:		// on an short US keyboard you cannot add an comment, IK_OEM_2 is the other "/"
		case IK_OEM_2:
		case 'C':			// alternate comment key
		{

			//Add eol comment on current line

			//get current line number
			int x = -1;
			int y = -1;

			y = get_custom_viewer_line_number(w, &x, &y);

			if (y == NULL) {
				return false;
			}
			dmsg("comment: x:%i y:%i\n", x, y);

			Decompiled* dec = function_map[w];

			// node name is $ blc+ startoffset of function, this avoids issues with renaming
			qstring nodename = NETNODEPRE;

			// generating netnode name and open that node
			//thanks Chris for your book :-) - page 294 f.

			string nodeappend = std::to_string((long)dec->ida_func->start_ea);

			nodename.append(nodeappend.c_str());

			netnode cno(nodename.c_str());

			// read existing comment if any

			int len = cno.supstr(y, NULL, 0);

			qstring comment;

			if (len > 1) {

				char* obuf = new char[len];		//allocate a buffer of sufficient size
				cno.supval(y, obuf, len);		//extract data from the supval

				comment = obuf;

			}

			// sorry only, one line comments for now
			// TODO: Allow multi lines 

			if (ask_str(&comment, HIST_CMT, "Please enter your comment")) {

				// save comment to a netnode
				// https://www.hex-rays.com/products/ida/support/sdkdoc/netnode_8hpp.html

				// check if node exists, if not create it
				if (cno == BADNODE) {
					cno.create(nodename.c_str());
				}

				//save comment at array index "linenumber"
				cno.supset(y, comment.c_str());

				refresh_widget(w);

				msg("Added comment \"%s\" on line %d\n", comment.c_str(), y);
			}

			return true;
		}
		// back
		case IK_ESCAPE: {
			map<TWidget*, qvector<ea_t> >::iterator mi = histories.find(w);
			if (mi != histories.end()) {
				qvector<ea_t>& v = mi->second;
				if (v.size() == 1) {
					close_widget(w, WCLS_DONT_SAVE_SIZE | WCLS_CLOSE_LATER);
					string t = views[w];
					views.erase(w);
					delete function_map[w];
					function_map.erase(w);
					titles.erase(t);
				}
				else {
					v.pop_back();
					decompile_at(v.back(), w);
				}
				return true;
			}
			break;
		}
					  // navigate to
		case IK_RETURN: {  //jump to symbol under cursor
			return navigate_to_word(w, false);
		}
		default:
			dmsg("Detected key press: 0x%x\n", key);
			break;
		}
	}
	return false;
}



static bool idaapi ct_dblclick(TWidget* cv, int shift, void* ud) {
	//   msg("Double clicked on: %s\n", word.c_str());
	return navigate_to_word(cv, true);
}

static const custom_viewer_handlers_t handlers(
	ct_keyboard,
	NULL, // popup
	NULL, // mouse_moved
	NULL, // click
	ct_dblclick, // dblclick
	NULL, //ct_curpos,
	NULL, // close
	NULL, // help
	NULL);// adjust_place

string ghidra_dir;

map<int, string> proc_map;

map<int, string> return_reg_map;

int blc_init_old(void);

static const char *name_dialog;

#if IDA_SDK_VERSION >= 750	
plugmod_t* idaapi blc_init_new(void);
#elif IDA_SDK_VERSION > 740	
size_t idaapi blc_init_new(void);
#else
int idaapi blc_init_new(void);
#endif

void idaapi blc_term(void);

//get the format string for IDA's standard rename dialog
void find_ida_name_dialog() {
	help_t i;
	for (i = 0; ; i++) {
		const char* hlp = itext(i);
		const char* lf = strchr(hlp, '\n');
		if (lf != NULL) {
			lf++;
			if (strncmp("Rename address\n", lf, 15) == 0) {
				name_dialog = hlp;
				//            msg("Found:\n%s\n", hlp);
				break;
			}
		}
	}
}

// return -1 - name is not associated with a symbol
// return 0  - duplicate name
// return 1  - no change
// return 2  - name changed
// return 3  - new name, but couldn't change it
int do_ida_rename(qstring& name, ea_t func) {
	ea_t name_ea = get_name_ea(func, name.c_str());
	if (name_ea == BADADDR) {
		//somehow the original name is invalid
		dmsg("rename: %s has no addr\n", name.c_str());
		return -1;
	}
	qstring orig = name;
	bool res = ask_str(&name, HIST_IDENT, "Please enter item name");
	if (res && name != orig) {
		ea_t new_name_ea = get_name_ea(func, name.c_str());
		if (new_name_ea != BADADDR) {
			//new name is same as existing name
			msg("rename: new name already in use\n", name.c_str());
			return 0;
		}
		//      msg("Custom rename: %s at adddress 0x%zx\n", name.c_str(), name_ea);
		res = set_name(name_ea, name.c_str());
		return res ? 2 : 3;
	}
	//   msg("rename: no change\n");
	return 1;
}

void init_ida_ghidra() {
	const char* ghidra = getenv("GHIDRA_DIR");
	if (ghidra) {
		ghidra_dir = ghidra;
	}
	else {
		ghidra_dir = idadir("plugins");
	}
	//   find_ida_name_dialog();

	arch_map[PLFM_MIPS] = mips_setup;

	proc_map[PLFM_6502] = "6502";
	proc_map[PLFM_68K] = "68000";
	proc_map[PLFM_6800] = "6805";
	//proc_map[PLFM_xxx] = "8048";
	proc_map[PLFM_8051] = "8051";
	//proc_map[PLFM_Z80] = "8085";
	proc_map[PLFM_ARM] = "ARM";
	//proc_map[PLFM_ARM] = "AARCH64";
	proc_map[PLFM_AVR] = "Atmel";
	proc_map[PLFM_CR16] = "CR16";
	proc_map[PLFM_DALVIK] = "Dalvik";
	proc_map[PLFM_JAVA] = "JVM";
	proc_map[PLFM_MIPS] = "MIPS";
	proc_map[PLFM_HPPA] = "pa-risc";
	proc_map[PLFM_PIC] = "PIC";
	proc_map[PLFM_PPC] = "PowerPC";
	proc_map[PLFM_SPARC] = "sparc";
	proc_map[PLFM_MSP430] = "TI_MSP430";
	proc_map[PLFM_TRICORE] = "tricore";
	proc_map[PLFM_386] = "x86";
	proc_map[PLFM_Z80] = "Z80";
#if NEWPROCS	
	proc_map[PLFM_NEC_V850X] = "V850";
#endif

	return_reg_map[PLFM_6502] = "6502";
	return_reg_map[PLFM_68K] = "68000";
	return_reg_map[PLFM_6800] = "6805";
	//return_reg_map[PLFM_xxx] = "8048";
	return_reg_map[PLFM_8051] = "8051";
	//return_reg_map[PLFM_Z80] = "8085";
	return_reg_map[PLFM_ARM] = "r0:r0:r0:r0";
	//return_reg_map[PLFM_ARM] = "r0:r0:r0:r0";
	return_reg_map[PLFM_AVR] = "Atmel";
	return_reg_map[PLFM_CR16] = "CR16";
	return_reg_map[PLFM_DALVIK] = "Dalvik";
	return_reg_map[PLFM_JAVA] = "JVM";
	return_reg_map[PLFM_MIPS] = "v0:v0:v0:v0";
	return_reg_map[PLFM_HPPA] = "PA-RISC";
	return_reg_map[PLFM_PIC] = "PIC";
	return_reg_map[PLFM_PPC] = "PowerPC";
	return_reg_map[PLFM_SPARC] = "Sparc";
	return_reg_map[PLFM_MSP430] = "TI_MSP430";
	return_reg_map[PLFM_TRICORE] = "tricore";
	return_reg_map[PLFM_386] = "al:ax:eax:rax";
	return_reg_map[PLFM_Z80] = "Z80";
#if NEWPROCS	
	return_reg_map[PLFM_NEC_V850X] = "V850";
#endif

	type_sizes["void"] = 1;
	type_sizes["bool"] = 1;
	type_sizes["uint1"] = 1;
	type_sizes["uint2"] = 2;
	type_sizes["uint4"] = 4;
	type_sizes["uint8"] = 8;
	type_sizes["int1"] = 1;
	type_sizes["int2"] = 2;
	type_sizes["int4"] = 4;
	type_sizes["int8"] = 8;
	type_sizes["float4"] = 4;
	type_sizes["float8"] = 8;
	type_sizes["float10"] = 10;
	type_sizes["float16"] = 16;
	type_sizes["xunknown1"] = 1;
	type_sizes["xunknown2"] = 2;
	type_sizes["xunknown4"] = 4;
	type_sizes["xunknown8"] = 8;
	type_sizes["code"] = 1;
	type_sizes["char"] = 1;
	type_sizes["wchar2"] = 2;
	type_sizes["wchar4"] = 4;
}

#if IDA_SDK_VERSION < 730

#define WOPN_DP_TAB WOPN_TAB

bool inf_is_64bit() {
	return inf.is_64bit();
}

bool inf_is_32bit() {
	return inf.is_32bit();
}

void inf_get_cc(compiler_info_t* cc) {
	*cc = inf.cc;
}

bool inf_is_be() {
	return inf.is_be();
}

filetype_t inf_get_filetype() {
	return (filetype_t)inf.filetype;
}

#endif

int get_proc_id() {
#if IDA_SDK_VERSION < 750
   return ph.id;
#else
   return PH.id;
#endif
}

bool get_sleigh_id(string &sleigh) {
   sleigh.clear();
   map<int,string>::iterator proc = proc_map.find(get_proc_id());
   if (proc == proc_map.end()) {
      return false;
   }
   compiler_info_t cc;
   inf_get_cc(&cc);
   bool is_64 = inf_is_64bit();
   bool is_be = inf_is_be();
   filetype_t ftype = inf_get_filetype();

	sleigh = proc->second + (is_be ? ":BE" : ":LE");

   switch (get_proc_id()) {
      case PLFM_6502:
         sleigh += ":16:default";
         break;
      case PLFM_68K:
         //options include "default" "MC68030" "MC68020" "Coldfire"
         sleigh += ":32:default";
         break;
      case PLFM_6800:
         sleigh += ":8:default";
         break;
      case PLFM_8051:
         sleigh += ":16:default";
         break;
      case PLFM_ARM:
         //options include "v8" "v8T" "v8LEInstruction" "v7" "v7LEInstruction" "Cortex"
         //                "v6" "v5t" "v5" "v4t" "v4" "default"
         if (is_64) {  //AARCH64
            sleigh = "AARCH64";
            sleigh += (is_be ? ":BE:64:v8A" : ":LE:64:v8A");
         }
         else {
            sleigh += ":32:v7";
         }
         break;
      case PLFM_AVR:
         sleigh += ":16:default";
         break;
      case PLFM_CR16:
         sleigh += ":16:default";
         break;
      case PLFM_DALVIK:
         sleigh += ":32:default";
         break;
      case PLFM_JAVA:
         sleigh += ":32:default";
         break;
      case PLFM_MIPS: {
         //options include "R6" "micro" "64-32addr" "micro64-32addr" "64-32R6addr" "default"
         qstring abi;
         if (get_abi_name(&abi) > 0 && abi.find("n32") == 0) {
            sleigh += ":64:64-32addr";
         }
         else {
            sleigh += is_64 ? ":64:default" : ":32:default";
         }
         break;
      }
      case PLFM_HPPA:
         sleigh += ":32:default";
         break;
      case PLFM_PIC:
         break;
      case PLFM_PPC: {
         //options include "default" "64-32addr" "4xx" "MPC8270" "QUICC" "A2-32addr"
         //                "A2ALT-32addr" "A2ALT" "VLE-32addr" "VLEALT-32addr"
         qstring abi;
         if (get_abi_name(&abi) > 0 && abi.find("xbox") == 0) {
            // ABI name is set to "xbox" for X360 PPC executables
            sleigh += ":64:A2ALT-32addr";
         }
         else {
            sleigh += is_64 ? ":64:default" : ":32:default";
         }
         break;
      }
      case PLFM_SPARC:
         sleigh += is_64 ? ":64" : ":32";
         sleigh += ":default";
         break;
      case PLFM_MSP430:
         sleigh += ":16:default";
         break;
      case PLFM_TRICORE:
         sleigh += ":32:default";
         break;
      case PLFM_386:
         //options include "System Management Mode" "Real Mode" "Protected Mode" "default"
         sleigh += is_64 ? ":64" : (inf_is_32bit() ? ":32" : ":16");
         if (sleigh.find(":16") != string::npos) {
            sleigh += ":Real Mode";
         }
         else {
            sleigh += ":default";
         }

		if (cc.id == COMP_BC) {
			sleigh += ":borlandcpp";
		}
		else if (cc.id == COMP_MS) {
			sleigh += ":windows";
		}
		else if (cc.id == COMP_GNU) {
			sleigh += ":gcc";
		}
		break;
	case PLFM_Z80:
		break;
#if NEWPROCS		
	case PLFM_NEC_V850X:
		sleigh += ":32:default";
		break;
#endif		
	default:
		return false;
	}

	return true;
}

void get_ida_bytes(uint8_t* buf, uint64_t size, uint64_t ea) {
	get_bytes(buf, size, (ea_t)ea);
}

bool does_func_return(void* func) {
	func_t* f = (func_t*)func;
	return func_does_return(f->start_ea);
}

uint64_t get_func_start(void* func) {
	func_t* f = (func_t*)func;
	return f->start_ea;
}

uint64_t get_func_start(uint64_t ea) {
	func_t* f = get_func((ea_t)ea);
	return f ? f->start_ea : BADADDR;
}

uint64_t get_func_end(uint64_t ea) {
	func_t* f = get_func((ea_t)ea);
	return f ? f->end_ea : BADADDR;
}

//Create a Ghidra to Ida name mapping for a single loval variable (including formal parameters)
void map_var_from_decl(Decompiled* dec, VarDecl* decl) {
	Function* ast = dec->ast;
	func_t* func = dec->ida_func;
	struc_t* frame = get_frame(func);
	ea_t ra = frame_off_retaddr(func);
	const string gname = decl->getName();
	size_t stack = gname.find("Stack");
	LocalVar* lv = new LocalVar(gname, gname);  //default current name will be ghidra name
	if (stack != string::npos) {         //if it's a stack var, change current to ida name
		uint32_t stackoff = strtoul(&gname[stack + 5], NULL, 0);
		member_t* var = get_member(frame, ra - stackoff);
		lv->offset = ra - stackoff;
		if (var) {                        //now we know there's an ida name assigned
			qstring iname;
			get_member_name(&iname, var->id);
			ast->rename(gname, iname.c_str());
			dec->locals[iname.c_str()] = lv;
			lv->current_name = iname.c_str();
		}
		else {  //ghidra says there's a variable here, let's name it in ida
		   //TODO - need to compute sizeof(decl) to properly create
		   //       the new data member
			qstring iname;
			iname.sprnt("var_%X", stackoff - func->frregs);
			if (add_struc_member(frame, iname.c_str(), ra - stackoff, byte_flag(), NULL, 1) == 0) {
				ast->rename(gname, iname.c_str());
				dec->locals[iname.c_str()] = lv;
				lv->current_name = iname.c_str();
			}
			else {
				dec->locals[gname] = lv;
			}
		}
	}
	else {  //handle non-stack (register) local variables
		netnode nn(dec->ida_func->start_ea);
		qstring iname;
		if (nn.hashstr(&iname, gname.c_str()) <= 0) {
			//no existing mapping
			dec->locals[gname] = lv;
		}
		else {
			//we already have a mapping for this ghidra variable
			ast->rename(gname, iname.c_str());
			dec->locals[iname.c_str()] = lv;
			lv->current_name = iname.c_str();
		}
	}
}

void map_ghidra_to_ida(Decompiled* dec) {
	Function* ast = dec->ast;
	vector<Statement*>& bk = ast->block.block;
	vector<VarDecl*>& parms = ast->prototype.parameters;

	//add mappings for formal parameter names
	for (vector<VarDecl*>::iterator i = parms.begin(); i != parms.end(); i++) {
		VarDecl* decl = *i;
		map_var_from_decl(dec, decl);
	}

	//add mappings for variable names
	for (vector<Statement*>::iterator i = bk.begin(); i != bk.end(); i++) {
		VarDecl* decl = dynamic_cast<VarDecl*>(*i);
		if (decl) {
			map_var_from_decl(dec, decl);
		}
		else {
			break;
		}
	}
}

void decompile_at(ea_t addr, TWidget* w) {
	string xml;
	string cfunc;
	func_t* func = get_func(addr);
	Function* ast = NULL;
	if (func) {

		// We need to hard reset things to get the symboltab reloaded
		// dirty solution but best I came up with atm.
		// If we not refresh ist teh decompiler output will be broken in
		// certain situations, i.e. if something was changed outside the
		// decompiler window
		ghidra_init();

		int res = do_decompile(func->start_ea, func->end_ea, &ast);
		if (ast) {
			dmsg("got a Functon tree!\n");
			Decompiled* dec = new Decompiled(ast, func);

			// now try to map ghidra stack variable names to ida stack variable names
			dmsg("mapping ida names to ghidra names\n");
			map_ghidra_to_ida(dec);

			vector<string> code;

			// Generating C code
			dec->ast->print(&code);

			// Displaying C code
			strvec_t* sv = new strvec_t();

			dec->set_ud(sv);

			// build code view line by line from generated ast including comments

			qstring nodename = NETNODEPRE;

			string nodeappend = std::to_string((long)dec->ida_func->start_ea);

			nodename.append(nodeappend.c_str());

			netnode cno(nodename.c_str());

			int ci = 0; // lines start at 0 in IDA

			for (vector<string>::iterator si = code.begin(); si != code.end(); si++) {

				qstring pline = si->c_str();

				if (cno != BADNODE) {
					// get length of entry
					int len = cno.supstr(ci, NULL, 0);

					if (len > 1) {

						//allocate a buffer of sufficient size
						char* outstr = new char[len];

						// get the comment at the current line number in iteration from superval
						cno.supval(ci, outstr, len);

						// append it as comment
						pline.append(" // ");
						pline.append(outstr);

					}

					sv->push_back(simpleline_t(pline));

				}
				else {
					sv->push_back(simpleline_t(pline));
				}

				ci++;
			}

			qstring func_name;
			qstring fmt;

			get_func_name(&func_name, func->start_ea);

			// TODO: Improve tab titles
			string title = get_available_title();

			fmt.sprnt("Ghidra Code-%s", title.c_str());   // make the suffix change with more windows

			simpleline_place_t s1;
			simpleline_place_t s2((int)(sv->size() - 1));
			if (w == NULL) {

				// create new code viewer
				// sv = viewer content
				w = create_custom_viewer(fmt.c_str(), &s1, &s2, &s1, NULL, sv, &handlers, sv);

				TWidget* code_view = create_code_viewer(w);

				/// Specify that the given code viewer is used to display source code
				set_code_viewer_is_source(code_view);

				display_widget(code_view, WOPN_DP_TAB);

				histories[w].push_back(addr);
				views[w] = title;

				titles.insert(title);
			}
			else {

				// if viewer already exists

				callui(ui_custom_viewer_set_userdata, w, sv);

				refresh_custom_viewer(w);
				repaint_custom_viewer(w);

				delete function_map[w];
			}

			function_map[w] = dec;

		}
		//      msg("do_decompile returned: %d\n%s\n%s\n", res, code.c_str(), cfunc.c_str());
	}
}

const char* tag_remove(const char* tagged) {
	static qstring ll;
	tag_remove(&ll, tagged);
	return ll.c_str();
}

#if IDA_SDK_VERSION >= 750

struct blc_plugmod_t : public plugmod_t {
  /// Invoke the plugin.
  virtual bool idaapi run(size_t arg);

  /// Virtual destructor.
  virtual ~blc_plugmod_t();
};

plugmod_t *idaapi blc_init(void) {
   //do ida related init
   init_ida_ghidra();

   if (ghidra_init()) {
      return new blc_plugmod_t();
   }
   else {
      return NULL;
   }
}

blc_plugmod_t::~blc_plugmod_t(void) {
   ghidra_term();
}

bool idaapi blc_plugmod_t::run(size_t /*arg*/) {
   ea_t addr = get_screen_ea();
   decompile_at(addr);
   return true;
}

#define blc_run NULL
#define blc_term NULL

#else

//make life easier in a post 7.5 world
#define PLUGIN_MULTI 0

int idaapi blc_init(void) {
   //do ida related init
   init_ida_ghidra();

   if (ghidra_init()) {
      return PLUGIN_KEEP;
   }
   else {
      return PLUGIN_SKIP;
   }
}

void idaapi blc_term(void) {
   ghidra_term();
}

bool idaapi blc_run(size_t /*arg*/) {
	ea_t addr = get_screen_ea();
	decompile_at(addr);
	return true;
}
#endif

int64_t get_name(string& name, uint64_t ea, int flags) {
	qstring ida_name;
	int64_t res = get_name(&ida_name, (ea_t)ea, flags);
	if (res > 0) {
		name = ida_name.c_str();
	}
	return res;
}

int64_t get_func_name(string& name, uint64_t ea) {
	qstring ida_name;
	int64_t res = get_func_name(&ida_name, (ea_t)ea);
	if (res > 0) {
		name = ida_name.c_str();
	}
	return res;
}

bool is_function_start(uint64_t ea) {
	func_t* f = get_func((ea_t)ea);
	return f != NULL && f->start_ea == (ea_t)ea;
}

void get_input_file_path(string& path) {
	char buf[512];
	get_input_file_path(buf, sizeof(buf));
	path = buf;
}

bool is_thumb_mode(uint64_t ea) {
	return get_sreg((ea_t)ea, 20) == 1;
}

//is ea a function internal jump target, if so
//return true and place its name in name
//else return false
bool is_code_label(uint64_t ea, string& name) {
	xrefblk_t xr;
	for (bool success = xr.first_to((ea_t)ea, XREF_ALL); success; success = xr.next_to()) {
		if (xr.iscode == 0) {
			break;
		}
		if (xr.type != fl_JN) {
			continue;
		}
		qstring ida_name;
		int64_t res = get_name(&ida_name, (ea_t)ea, GN_LOCAL);
		if (res > 0) {
			name = ida_name.c_str();
			return true;
		}
	}
	return false;
}
/*
	check if adress is extern by validating the segment type in which ea is located
	or checking for common segment names
*/
bool is_extern_addr(uint64_t ea) {

	qstring sname, stype;
	segment_t* s = getseg(ea);

	if (s) {

		get_segm_name(&sname, s);
		get_segm_class(&stype, s);

		dmsg("is_extern_addr ea: %x %s %s\n", ea, sname.c_str(), stype.c_str());

		if (stype == "XTRN" || 
			//strcmp return 0 if equal!
			!strcmp(sname.c_str(), "extern") ||		// name in a lot of ELF Binaries
			!strcmp(sname.c_str(), ".idata"))		// name in PE bins on Windows
		{
			dmsg("is_extern_addr true\n");
			return true;
		}
	}
	return false;
}

bool is_external_ref(uint64_t ea, uint64_t* fptr) {
	ea_t got;
	func_t* pfn = get_func((ea_t)ea);
	if (pfn == NULL) {
		return false;
	}
	if (is_extern_addr(pfn->start_ea)) {
		if (fptr) {
			*fptr = pfn->start_ea;
		}
		return true;
	}
	ea_t _export = calc_thunk_func_target(pfn, &got);
	bool res = _export != BADADDR;
	if (res) {
		if (fptr) {
			*fptr = got;
		}
		dmsg("0x%zx is external, with got entry at 0x%zx\n", ea, (size_t)got);
	}
	return res;
}

bool is_extern(const string& name) {
	bool res = false;
	ea_t ea = get_name_ea(BADADDR, name.c_str());
	if (ea == BADADDR) {
		dmsg("is_extern called for %s (BADADDR)\n", name.c_str());
		return false;
	}
	if (is_function_start(ea)) {
		dmsg("is_extern - is_function_start\n");
		res = is_external_ref(ea, NULL);
	}
	else {
		res = is_extern_addr(ea);
	}
#if DEBUG_PLUGIN
	if ((res == false) && true) {
		
		// code for debugging xrefs

		//decode insn to get assembly command
		insn_t ida_instruction;

		if (decode_insn(&ida_instruction, ea) <= 0) {
			return false;
		}

		dmsg("is_indirect_jump_insn = %d\n", is_indirect_jump_insn(ida_instruction));
		dmsg("is_call_insn  = %d\n", is_call_insn(ida_instruction));

		string astring;
		dmsg("is_code_label = %d\n", is_code_label(ea, astring));
	}
#endif
	dmsg("is_extern called for %s (%d)\n", name.c_str(), res);
	return res;
}

bool address_of(const string& name, uint64_t* addr) {
	bool res = false;
	ea_t ea = get_name_ea(BADADDR, name.c_str());
	if (ea == BADADDR) {
		return false;
	}
	*addr = ea;
	return true;
}

bool is_library_func(const string& name) {
	bool res = false;
	ea_t ea = get_name_ea(BADADDR, name.c_str());
	if (is_function_start(ea)) {
		func_t* f = get_func(ea);
		res = f ? (f->flags & FUNC_LIB) != 0 : false;
	}
	return res;
}

bool is_named_addr(uint64_t ea, string& name) {
	qstring res;
	//a sanity check on ea
	segment_t* s = getseg(0);
	if (s != NULL && ea < s->end_ea) {
		//ea falls in first segment of zero based binary
		//this are generally headers and ea is probably
		//not a pointer but instead just a small number
		return false;
	}
	if (get_name(&res, (ea_t)ea) > 0) {
		name = res.c_str();
		return true;
	}
	return false;
}

bool is_pointer_var(uint64_t ea, uint32_t size, uint64_t* tgt) {
	xrefblk_t xb;
	if (xb.first_from(ea, XREF_DATA) && xb.type == dr_O) {
		// xb.to - contains the referenced address
		*tgt = xb.to;
		return true;
	}
	return false;
}

bool is_read_only(uint64_t ea) {
	qstring sname;
	segment_t* s = getseg(ea);
	if (s) {
		if ((s->perm & SEGPERM_WRITE) == 0) {
			return true;
		}
		//not explicitly read only, so let's make some guesses
		//based on the segment name
		get_segm_name(&sname, s);
		if (sname.find("got") <= 1) {
			return true;
		}
		if (sname.find("rodata") <= 1) {
			return true;
		}
		if (sname.find("rdata") <= 1) {
			return true;
		}
		if (sname.find("idata") <= 1) {
			return true;
		}
		if (sname.find("rel.ro") != qstring::npos) {
			return true;
		}
	}
	return false;
}

bool simplify_deref(const string &name, string &new_name) {
   uint64_t tgt;
   ea_t addr = get_name_ea(BADADDR, name.c_str());
#if IDA_SDK_VERSION < 750
   uint32_t max_ptr_size = (uint32_t)ph.max_ptr_size();
#else
   uint32_t max_ptr_size = (uint32_t)PH.max_ptr_size();
#endif
   if (addr != BADADDR && is_read_only(addr) && is_pointer_var(addr, max_ptr_size, &tgt)) {
      if (get_name(new_name, tgt, 0)) {
//         msg("could simplify *%s to %s\n", name.c_str(), new_name.c_str());
         return true;
      }
   }
   return false;
}

void adjust_thunk_name(string& name) {

	ea_t ea = get_name_ea(BADADDR, name.c_str());

	dmsg("adjust_thunk_name(%s)\n", name.c_str());

	if (is_function_start(ea)) {

		func_t* f = get_func(ea);
		ea_t fun = calc_thunk_func_target(f, &ea);

		if (fun != BADADDR) {

			qstring tname;

			//this seems to return success even on failure, e.g. in the debugger
			get_name(&tname, fun);

			string stname = tname.c_str();

			if (!stname.empty()) {
				dmsg("	adjust_thunk_name: setting new name \"%s\"\n", tname.c_str());
				name = tname.c_str();
			}
		}
	}

}

//TODO think about sign extension for values smaller than 8 bytes
bool get_value(uint64_t addr, uint64_t* val) {
	flags_t f = get_full_flags(addr);
	if (is_qword(f)) {
		*val = get_qword(addr);
	}
	else if (is_dword(f)) {
		*val = get_dword(addr);
	}
	else if (is_byte(f)) {
		*val = get_byte(addr);
	}
	else if (is_word(f)) {
		*val = get_word(addr);
	}
	else {
		return false;
	}
	return true;
}

// TODO: optimize with new functions
bool get_string(uint64_t addr, string& str) {
	qstring res;
	flags_t f = get_full_flags(addr);

	if (is_strlit(f)) {
		get_strlit_contents(&res, addr, -1, STRTYPE_C);
		str = res.c_str();
		return true;
	}
	else if (!is_data(f)) {
		size_t maxlen = get_max_strlit_length(addr, STRTYPE_C);
		if (maxlen > 4) {
			create_strlit(addr, 0, STRTYPE_C);
			get_strlit_contents(&res, addr, -1, STRTYPE_C);
			str = res.c_str();
			return true;
		}
	}
	return false;
}

bool get_str_lit(uint64_t addr, string* str) {

	qstring res;

	flags_t f = get_full_flags(addr);

	//msg("get_str_lit(): %x\n",addr);

	if (is_strlit(f)) {

		//msg("get_str_lit(): is_strlit()\n");

		get_strlit_contents(&res, addr, -1, STRTYPE_C);

		*str = res.c_str();

		return true;
	}
	//try to resolve another way...
	if (is_off(f, OPND_ALL)) {

		refinfo_t ri;

		get_refinfo(&ri, addr, OPND_ALL);

		//msg("get_str_lit(): refbase %x target %x\n", ri.base, ri.target);

		uval_t v; //target addr

		get_data_value(&v, addr, 0);

		//msg("get_str_lit(): %x is offset with target %x\n", addr, v);

		get_str_lit(ri.base + v, str);

		return true;

	}

	return false;
}


bool get_string_ea(uint64_t addr, string* str) {

	qstring res;

	get_str_lit(addr, str);

	if (*str != "") {
		return true;
	}

	flags_t f = get_full_flags(addr);

	if (is_off(f, OPND_ALL)) {

		//msg("is Offset\n");

		refinfo_t ri;

		get_refinfo(&ri, addr, OPND_ALL);

		if (ri.target != BADADDR) {

			//untested
			get_str_lit(ri.target, str);

		}
		else if (is_code(f)) {

			// shamelessly borrowed from the NSA:
			// https://github.com/NationalSecurityAgency/ghidra/blob/21f4802c2a9930ef3447f70d37f391b91c3cda5b/GhidraBuild/IDAPro/Python/6xx/plugins/xmlexp.py

			insn_t out;
			decode_insn(&out, addr);

			ea_t value = out.ops->addr;

			ea_t target = value - ri.tdelta + ri.base;

			get_str_lit(target, str);

			dmsg("CODE: offset %x\n", addr);

		}
		else if (is_data(f)) {

			uval_t v;

			get_data_value(&v, addr, 0);

			get_str_lit(v, str);

			dmsg("DATA: offset %x %x\n", addr, v);

		}

	}

	if (*str != "") {
		return true;
	}

	return false;
}

string get_string(const string& name) {

	ea_t ea = get_name_ea(BADADDR, name.c_str());
	string str;

	bool res = get_string_ea(ea, &str);

	/*	if (!res) {
			msg("Error getting string for %s (ea: %x)\n", name.c_str(), ea);
		}
		else {
			msg("str: %s\n", str.c_str());
		}
	*/
	return str.c_str();
}

bool is_string(const string& name) {

	ea_t ea = get_name_ea(BADADDR, name.c_str());

	if (ea == BADADDR) {
		return false;
	}

	qstring sname;
	segment_t* s = getseg(ea);
	if (s) {
		get_segm_name(&sname, s);

		if (strstr(sname.c_str(), "string")) {
			return true;
		}
	}
	return false;
}

void print_blc_banner() {
	if (!sleigh_id.c_str())
		msg("Ghidra Decompiler (blc) - CPU not supported!\n");
	else {
		msg("Ghidra Decompiler (blc) ready.\nUsing sleigh id: %s\n", sleigh_id.c_str());
	}
}

#if IDA_SDK_VERSION >= 750	
plugmod_t* idaapi blc_init_new(void) {

	plugmod_t* res = blc_init();
	
	print_blc_banner();

	return res;
}
#elif IDA_SDK_VERSION >= 740	
size_t idaapi blc_init_new(void) {

	size_t res = blc_init();

	print_blc_banner();

	return res;
}
#else
int idaapi blc_init_new(void) {
	int res = blc_init();

	print_blc_banner();

	return res;
}
#endif

//--------------------------------------------------------------------------
char comment[] = "Ghidra decompiler integration.";

char help[] = "I have nothing to offer.\n";

char wanted_name[] = "Ghidra Decompiler";

char wanted_hotkey[] = "Alt-F3";

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,      // plugin flags
  blc_init_new,          // initialize
  blc_term,          // terminate. this pointer may be NULL.
  blc_run,           // invoke plugin
  comment,              // long comment about the plugin
						// it could appear in the status line
						// or as a hint
  help,                 // multiline help about the plugin
  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
