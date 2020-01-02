/*
   Source for the blc IdaPro plugin
   Copyright (c) 2019 Chris Eagle

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
*/

#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <stdint.h>
#include <stdlib.h>

using std::iostream;
using std::ifstream;
using std::ostringstream;
using std::map;

#include "libdecomp.hh"
#include "capability.hh"
#include "sleigh_arch.hh"
#include "xml.hh"

#include "plugin.hh"
#include "ida_minimal.hh"
#include "ida_arch.hh"
#include "ast.hh"

stringstream *err_stream;

static string sleigh_id;
ida_arch *arch;  // in lieu of Architecture *IfaceDecompData::conf

void escape_value(const string &value, string &res) {
   const char *content = value.c_str();
   while (*content) {
      if (*content == '&') {
         res += "&amp;";
      }
      else if (*content == '>') {
         res += "&gt;";
      }
      else if (*content == '<') {
         res += "&lt;";
      }
      else if (*content == '"') {
         res += "&quot;";
      }
      else if (*content == '\'') {
         res += "&apos;";
      }
      else {
         res += *content;
      }
      content++;
   }
}

void dump_el(const Element *el, int indent, string &res) {
   const List &children = el->getChildren();

   int clen = el->getContent().length();

   int nattr = el->getNumAttributes();

   res.append(indent, ' ');
   res.push_back('<');
   res += el->getName();

   for (int i = 0; i < nattr; i++) {
      res.push_back(' ');
      res += el->getAttributeName(i);
      res += "=\"";
      escape_value(el->getAttributeValue(i).c_str(), res);
      res += "\"";
   }

   int nchildren = 0;

   for (List::const_iterator it = children.begin(); it != children.end(); it++) {
      const Element *child = *it;
      nchildren++;
      if (nchildren == 1) {
         res += ">\n";
      }
      dump_el(child, indent + 3, res);
   }
   if (nchildren) {
      if (el->getContent().length() > 0) {
         res += "NON-ZERO content in element with children\n";
      }
      res.append(indent, ' ');
      res += "</";
      res += el->getName();
      res += ">\n";
   }
   else {
      if (clen) {
         res += ">";
         escape_value(el->getContent().c_str(), res);
         res += "</";
         res += el->getName();
         res += ">\n";
      }
      else {
         res += "/>\n";
      }
   }
}

static const string empty_string("");

const string &getAttributeValue(const Element *el, const char *attr) {
   int nattr = el->getNumAttributes();

   for (int i = 0; i < nattr; i++) {
      if (el->getAttributeName(i) == attr) {
         return el->getAttributeValue(i);
      }
   }
   return empty_string;
}

void check_err_stream() {
   if (err_stream->tellp()) {
      msg("%s\n", err_stream->str().c_str());
      err_stream->str("");
   }
}

TrackedSet &get_tracked_set(uint64_t start, uint64_t end) {
   //need to add a TrackedSet to arch->context(which is a ContextInternal for us)->trackbase
   //if we are tracking any registers. In particular, if any registers are fixed on entry
   //we should add them to the TrackedSet for ea. This is probabaly more useful for some archs
   //than others.
   AddrSpace *as = arch->getSpaceByName("ram");
   Address func_begin(as, start);
   Address func_end(as, end);
   return arch->context->createSet(func_begin, func_end);
}

void add_tracked_reg(TrackedSet &regs, uint64_t offset, uint64_t value, uint32_t size) {
   regs.push_back(TrackedContext());
   TrackedContext &reg = regs.back();
   reg.loc.space = arch->getSpaceByName("register");
   reg.loc.offset = offset;
   reg.loc.size = size;
   reg.val = value;
}

void mips_setup(uint64_t start, uint64_t end) {
   TrackedSet &regs = get_tracked_set(start, end);
   
   //this is very n64 specific
   // this is $t9 - need to do this better
   add_tracked_reg(regs, 0xc8, start, 8);
   add_tracked_reg(regs, 0xcc, start & 0xffffffffll, 4);
   add_tracked_reg(regs, 0xc8, start >> 32, 4);
}

int idaapi blc_init(void) {
   //init_query_handlers();

   //do ida related init
   init_ida_ghidra();

   startDecompilerLibrary(ghidra_dir.c_str());

   err_stream = new stringstream();

//   IfaceCapability::registerAllCommands(term);  // Register commands for decompiler and all modules

   string filename;
   get_input_file_path(filename);

   get_sleigh_id(sleigh_id);

   //implement most of IfcLoadFile::execute here since file is
   //already loaded in IDA

   arch = new ida_arch(filename, sleigh_id, err_stream);

   DocumentStorage store;  // temporary storage for xml docs

   string errmsg;
   bool iserror = false;
   try {
      arch->init(store);
      //at this point we have arch->context (a ContextInternal) available
      // we can do things like:
      // context->setVariableDefault("addrsize",1);  // Address size is 32-bits
      // context->setVariableDefault("opsize",1);    // Operand size is 32-bits
      // that make sense for our architecture
   } catch(XmlError &err) {
      errmsg = err.explain;
      iserror = true;
   } catch(LowlevelError &err) {
      errmsg = err.explain;
      iserror = true;
   }
   if (iserror) {
      msg("%s\n", errmsg.c_str());
      msg("Could not create architecture\n");
      delete arch;
      arch = NULL;
      return PLUGIN_SKIP;
   }

   check_err_stream();

   msg("Ghidra architecture successfully created\n");

   return PLUGIN_KEEP;
}

void idaapi blc_term(void) {
   shutdownDecompilerLibrary();

//   GhidraCapability::shutDown();
   delete err_stream;
   err_stream = NULL;
}

// Extract the info that the decompiler needs to instantiate its address space manager
// This also builds the internal register map while it walks the sleigh spec.

// see IfcDecompile::execute
int do_decompile(uint64_t start_ea, uint64_t end_ea, Function **result) {
   Scope *global = arch->symboltab->getGlobalScope();
   Address addr(arch->getDefaultSpace(), start_ea);
   Funcdata *fd = global->findFunction(addr);
   *result = NULL;

   if (strncmp("ARM", sleigh_id.c_str(), 3) == 0) {
      //if ARM check for and set thumb ranges
      if (is_thumb_mode(start_ea)) {
         arch->context->setVariable("TMode", addr, 1);
      }
   }

   int4 res = -1;
   if (fd) {
      string xml;
      string c_code;

      string func_name;
      get_func_name(func_name, start_ea);

//      msg("Decompiling %s\n", func_name.c_str());

      arch->clearAnalysis(fd); // Clear any old analysis

      arch_map_t::iterator setup = arch_map.find(get_proc_id());
      if (setup != arch_map.end()) {
         (*setup->second)(start_ea, end_ea);
      }

      arch->allacts.getCurrent()->reset(*fd);

      try {
          res = arch->allacts.getCurrent()->perform(*fd);
      }
      catch (DataUnavailError &err) {
          msg("Could not decompile function at 0x%x\n - %s", start_ea, err.explain.c_str());
          check_err_stream();
          return -1;
      }

      if (res < 0) {
         ostringstream os;
//         msg("Break at ");
         arch->allacts.getCurrent()->printState(os);
         msg("%s\n", os.str().c_str());
      }
      else {
//         msg("Decompilation complete");
         if (res == 0) {
//            msg(" (no change)");
         }
         stringstream ss;
         arch->print->setIndentIncrement(3);
         arch->print->setOutputStream(&ss);

         //print as C
         arch->print->docFunction(fd);
         c_code = ss.str();
         ss.str("");

         arch->print->setXML(true);
         arch->print->docFunction(fd);
         arch->print->setXML(false);
         xml = ss.str();

         //print the xml
         Document *doc = xml_tree(ss);

         if (doc) {
            string pretty;
            dump_el(doc->getRoot(), 0, pretty);
//            msg("%s\n", pretty.c_str());

            *result = func_from_xml(doc->getRoot(), start_ea);
//            msg("%s\n", c_code.c_str());
         }
      }
      check_err_stream();
   }
   else {
//      msg("Error, no Funcdata at 0x%x\n", (uint32_t)ea);
   }
   return res;
}

