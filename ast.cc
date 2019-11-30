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

#include <stdint.h>
#include <stdlib.h>
#include <map>
#include <set>

#include "xml.hh"
#include "ast.hh"
#include "ida_minimal.hh"
#include "plugin.hh"

using std::map;
using std::set;

#ifdef DEBUG_AST
#define dmsg(x, ...) msg(x, ...)
#else
#define dmsg(x, ...)
#endif

enum ast_tag_t {
   ast_tag_null,
   ast_tag_syntax,
   ast_tag_break,
   ast_tag_funcproto,
   ast_tag_vardecl,
   ast_tag_return_type,
   ast_tag_type,
   ast_tag_variable,
   ast_tag_block,
   ast_tag_statement,
   ast_tag_funcname,
   ast_tag_op,
   ast_tag_label
};

enum op_keywords_t {
   kw_null,
   kw_if,
   kw_switch,
   kw_while,
   kw_return,
   kw_assign
};

static const string WHILE("while");
static const string DO("do");
static const string IF("if");
static const string ELSE("else");
static const string BREAK("break");
static const string DEFAULT("default");
static const string SWITCH("switch");
static const string CASE("case");
static const string GOTO("goto");
static const string RETURN("return");

static const string LBRACE("{");
static const string RBRACE("}");
static const string LPAREN("(");
static const string RPAREN(")");
static const string LBRACKET("[");
static const string RBRACKET("]");
static const string COLON(":");
static const string SEMICOLON(";");
static const string COMMA(",");

enum g_token {
   g_null,
   g_lbrace,
   g_rbrace,
   g_lparen,
   g_rparen,
   g_cond_close,
   g_lbracket,
   g_rbracket,
   g_and,
   g_xor,
   g_or,
   g_not,
   g_bnot,
   g_logical_and,
   g_logical_or,
   g_comma,
   g_semi,
   g_lshift,
   g_rshift,
   g_lt,
   g_lte,
   g_gt,
   g_gte,
   g_assign,
   g_eq,
   g_ne,
   g_plus,
   g_minus,
   g_mod,
   g_div,
   g_star,
   g_plus_eq,
   g_minus_eq,
   g_star_eq,
   g_div_eq,
   g_mod_eq,
   g_and_eq,
   g_or_eq,
   g_xor_eq,
   g_lshift_eq,
   g_rshift_eq,
   g_plusplus,
   g_minusminus,
   g_qmark,
   g_colon,

   g_break,
   g_keyword,
   g_var,
   g_funcname,
   g_const,
   g_type,
   g_eol_cmt,
   g_cmt_open,
   g_cmt_close,
   g_label,
   g_symbol,
   g_op
};

static map<string,ast_tag_t> tag_map;
static map<string,g_token> ops;
static set<string> binary_ops;
static set<string> unary_ops;
static map<string,op_keywords_t> op_map;
static set<string> reserved;

static const string empty_string("");

static void block_handler(const Element *el, Block *block);
//static Statement *inner_block(const Element *child);
static VarDecl *vardecl_handler(const Element *el);
static Statement *statement_handler(const Element *el);
static Expression *expr_handler(List::const_iterator &it, List::const_iterator &end, bool in_paren = false);
static Switch *switch_handler(List::const_iterator &it);
static Else *else_handler(List::const_iterator &it);
static DoWhile *do_handler(List::const_iterator &it);

static const string &getAttributeValue(const Element *el, const char *attr) {
   int nattr = el->getNumAttributes();

   for (int i = 0; i < nattr; i++) {
      if (el->getAttributeName(i) == attr) {
         return el->getAttributeValue(i);
      }
   }
   return empty_string;
}

// in some cases Ghidra uses <funcname> and others <op>, in all cases
// color="funcname" will be present
bool is_funcname_color(const Element *el) {
   return getAttributeValue(el, "color") == "funcname";
}

bool is_keyword_color(const Element *el) {
   return getAttributeValue(el, "color") == "keyword";
}

bool is_const_color(const Element *el) {
   return getAttributeValue(el, "color") == "const";
}

static const Element *find_child(const Element *el, const char *tag) {
   const List &children = el->getChildren();
   for (List::const_iterator it = children.begin(); it != children.end(); it++) {
      const Element *child = *it;
      if (child->getName() == tag) {
         return child;
      }
   }
   return NULL;
}

static const Element *get_child(List::const_iterator &it) {
   const Element *child = *it;
   dmsg("Processing %s/%s\n", child->getName().c_str(), child->getContent().c_str());
   return child;
}

const char *debug_print(AstItem *exp) {
   string l = exp->line;
   exp->line.clear();
   exp->print();
   string r = exp->line;
   exp->line = l;
   return tag_remove(r.c_str());
}

AstItem::AstItem() : no_indent(false), no_semi(false), is_prefix(false),
                     line_no(1), col_start(-1), col_end(-1),
                     color(COLOR_DEFAULT) {};

vector<string> *AstItem::cfunc;
string AstItem::line;
size_t AstItem::indent;
size_t AstItem::line_index;

void AstItem::flush(bool no_indent) {
   string spaces;
   if (!no_indent) {
      spaces.append(indent, ' ');
   }
   cfunc->push_back(spaces + line);
//   dmsg("append: %s\n", cfunc->back().c_str());
   line.clear();
   line_index = 0;
}

void AstItem::append(char ch, bool count) {
   line.push_back(ch);
   line_index += count ? 1 : 0;
}

void AstItem::color_on(char tag) {
   append(COLOR_ON, false);
   append(tag, false);
}

void AstItem::color_off(char tag) {
   append(COLOR_OFF, false);
   append(tag, false);
}

void AstItem::append(const char *v) {
   append(string(v));
}  

void AstItem::append(const string &v) {
   line.append(v);
   line_index += v.length();
}  

void AstItem::append_colored(char tag, const char *v) {
   append_colored(tag, string(v));
}

void AstItem::append_colored(char tag, const string &v) {
   color_on(tag);
   append(v);
   color_off(tag);
}

void brace_print(AstItem &item, bool final_append = true) {
   AstItem::append_colored(COLOR_SYMBOL, LBRACE);
   AstItem::flush();
   AstItem::indent += 3;
   item.print();
   AstItem::indent -= 3;
   AstItem::append_colored(COLOR_SYMBOL, RBRACE);
   if (final_append) {
      AstItem::flush();
   }
}

void Statement::print() {
   line += "<statement>";
}

void Type::print() {
   append_colored(COLOR_KEYWORD, name);
}

void Type::rename(const string &oldname, const string &newname) {
   if (oldname == name) {
      name = newname;
   }
}

void Expression::print() {
   line += "<expr>";
}

void LiteralExpr::print() {
   line += val;
}

void NameExpr::print() {
   append_colored(COLOR_DNAME, name);
}

void NameExpr::rename(const string &oldname, const string &newname) {
   dmsg("NameExpr::rename %s from %s to %s\n", name.c_str(), oldname.c_str(), newname.c_str());
   if (oldname == name) {
      name = newname;
   }
}

void FuncNameExpr::print() {
   if (is_extern(name)) {
      append_colored(COLOR_IMPNAME, name);
   }
   else if (is_library_func(name)) {
      append_colored(COLOR_DEFAULT, name);
   }
   else {
      append_colored(COLOR_DEFAULT, name);
   }
}

void FuncNameExpr::rename(const string &oldname, const string &newname) {
   if (oldname == name) {
      name = newname;
   }
}

void LabelExpr::print() {
   line += label;
}

void LabelExpr::rename(const string &oldname, const string &newname) {
   if (oldname == label) {
      label = newname;
   }
}

void LabelStatement::print() {
   line += label;
   append_colored(COLOR_SYMBOL, COLON);
}

void LabelStatement::rename(const string &oldname, const string &newname) {
   if (oldname == label) {
      label = newname;
   }
}

void GotoStatement::print() {
   append_colored(COLOR_KEYWORD, GOTO);
   append(' ');
   label->print();
}

void GotoStatement::rename(const string &oldname, const string &newname) {
   label->rename(oldname, newname);
}

void BreakStatement::print() {
   append_colored(COLOR_KEYWORD, BREAK);
}

ExprStatement::~ExprStatement() {
   delete expr;
}

void ExprStatement::print() {
   expr->print();
}

void ExprStatement::rename(const string &oldname, const string &newname) {
   expr->rename(oldname, newname);
}

CommaExpr::~CommaExpr() {
   delete lhs;
   delete rhs;
}

void CommaExpr::print() {
   lhs->print();
   append_colored(COLOR_SYMBOL, COMMA);
   append(' ');
   rhs->print();
}

void CommaExpr::rename(const string &oldname, const string &newname) {
   lhs->rename(oldname, newname);
   rhs->rename(oldname, newname);
}

void BinaryExpr::print() {
   lhs->print();
   line += ' ';
   color_on(COLOR_SYMBOL);
   line += op;
   color_off(COLOR_SYMBOL);
   line += ' ';
   rhs->print();
}

void BinaryExpr::rename(const string &oldname, const string &newname) {
   lhs->rename(oldname, newname);
   rhs->rename(oldname, newname);
}

void UnaryExpr::print() {
   color_on(COLOR_SYMBOL);
   line += op;
   color_off(COLOR_SYMBOL);
   expr->print();
}

void UnaryExpr::rename(const string &oldname, const string &newname) {
   expr->rename(oldname, newname);
}

void CastExpr::print() {
   line += type;
   color_on(COLOR_SYMBOL);
   line.append(deref, '*');
   color_off(COLOR_SYMBOL);
}

void CastExpr::rename(const string &oldname, const string &newname) {
   if (oldname == type) {
      type = newname;
   }
}

void TypeCast::print() {
   type->print();
   expr->print();
}

void TypeCast::rename(const string &oldname, const string &newname) {
   type->rename(oldname, newname);
   expr->rename(oldname, newname);
}

void NumericExpr::print() {
   line.append(val);
}

void StringExpr::print() {
   append_colored(COLOR_SYMBOL, "\"");
   line.append(val);
   append_colored(COLOR_SYMBOL, "\"");
}

void CharExpr::print() {
   append_colored(COLOR_SYMBOL, "'");
   line.append(val);
   append_colored(COLOR_SYMBOL, "'");
}

void ParenExpr::print() {
   append_colored(COLOR_SYMBOL, LPAREN);
   if (inner) {
      inner->print();
   }
   append_colored(COLOR_SYMBOL, RPAREN);
}

void ParenExpr::rename(const string &oldname, const string &newname) {
   if (inner) {
      dmsg("PArenExpr::rename from %s to %s\n", oldname.c_str(), newname.c_str());
      inner->rename(oldname, newname);
   }
}

void ArrayExpr::print() {
   array->print();
   append_colored(COLOR_SYMBOL, LBRACKET);
   index->print();
   append_colored(COLOR_SYMBOL, RBRACKET);
}

void ArrayExpr::rename(const string &oldname, const string &newname) {
   array->rename(oldname, newname);
   index->rename(oldname, newname);
}

void Block::print() {
   for (vector<Statement*>::iterator i = block.begin(); i != block.end(); i++) {
      Statement *s = *i;
      if (s) {
         s->print();
      }
      else {
         dmsg("Attempting to print a NULL Statement\n");
      }
      if (!s->no_semi) {
         append_colored(COLOR_SYMBOL, SEMICOLON);
      }
      flush(s->no_indent);
   }
}

void Block::rename(const string &oldname, const string &newname) {
   for (vector<Statement*>::iterator i = block.begin(); i != block.end(); i++) {
      Statement *s = *i;
      if (s) {
         dmsg("Block::rename from %s to %s\n", oldname.c_str(), newname.c_str());
         s->rename(oldname, newname);
      }
   }
}

void VarDecl::print() {
   type->print();
   append(' ');
   var->print();
}

const string &VarDecl::getName() {
   Expression *expr = var;
   while (true) {
      NameExpr *n = dynamic_cast<NameExpr*>(expr);
      if (n) {
         return n->name;
      }
      UnaryExpr *u = dynamic_cast<UnaryExpr*>(expr);
      if (u) {
         expr = u->expr;
         continue;
      }
      ParenExpr *p = dynamic_cast<ParenExpr*>(expr);
      if (p) {
         expr = p->inner;
         continue;
      }
      ArrayExpr *a = dynamic_cast<ArrayExpr*>(expr);
      if (a) {
         expr = a->array;
         continue;
      }
      dmsg("VarDecl unexpected expr type\n");
      return empty_string;
   }   
}

void VarDecl::rename(const string &oldname, const string &newname) {
   type->rename(oldname, newname);
   var->rename(oldname, newname);
   if (init) {
      init->rename(oldname, newname);
   }
}

void Funcproto::print() {
   return_type->print();
   for (vector<string>::iterator i = keywords.begin(); i != keywords.end(); i++) {
      append(' ');
      line += *i;
   }
   append(' ');
   line += name;
   append_colored(COLOR_SYMBOL, LPAREN);
   for (vector<VarDecl*>::iterator i = parameters.begin(); i != parameters.end(); i++) {
      if (i != parameters.begin()) {
         append_colored(COLOR_SYMBOL, COMMA);
         append(' ');
      }
      (*i)->print();
   }
   append_colored(COLOR_SYMBOL, RPAREN);
}

void Funcproto::rename(const string &oldname, const string &newname) {
   return_type->rename(oldname, newname);
   if (oldname == name) {
      name = newname;
   }
   for (vector<VarDecl*>::iterator i = parameters.begin(); i != parameters.end(); i++) {
      (*i)->rename(oldname, newname);
   }
}

CallExpr::~CallExpr() {
   delete func;
   delete args;
}

void CallExpr::print() {
   func->print();
   args->print();
}

void CallExpr::rename(const string &oldname, const string &newname) {
   dmsg("CallExpr::rename from %s to %s\n", oldname.c_str(), newname.c_str());
   func->rename(oldname, newname);
   args->rename(oldname, newname);
}

void Else::print() {
   append_colored(COLOR_KEYWORD, ELSE);
   append(' ');
   brace_print(block, false);
}

void Else::rename(const string &oldname, const string &newname) {
   block.rename(oldname, newname);
}

void If::print() {
   append_colored(COLOR_KEYWORD, IF);
   append(' ');
   append_colored(COLOR_SYMBOL, LPAREN);
   cond->print();
   append_colored(COLOR_SYMBOL, RPAREN);
   append(' ');
   brace_print(block, _else != NULL);
   if (_else) {
      _else->print();
   }
}

void If::rename(const string &oldname, const string &newname) {
   ConditionalStatement::rename(oldname, newname);
   if (_else) {
      _else->rename(oldname, newname);
   }
}

void ConditionalStatement::rename(const string &oldname, const string &newname) {
   dmsg("ConditionalStatement::rename from %s to %s\n", oldname.c_str(), newname.c_str());
   cond->rename(oldname, newname);
   block.rename(oldname, newname);
}

void While::print() {
   append_colored(COLOR_KEYWORD, WHILE);
   append(' ');
   append_colored(COLOR_SYMBOL, LPAREN);
   cond->print();
   append_colored(COLOR_SYMBOL, RPAREN);
   append(' ');
   brace_print(block, false);
}

void DoWhile::print() {
   append_colored(COLOR_KEYWORD, DO);
   append(' ');
   brace_print(block, false);
   append(' ');
   append_colored(COLOR_KEYWORD, WHILE);
   append(' ');
   append_colored(COLOR_SYMBOL, LPAREN);
   cond->print();
   append_colored(COLOR_SYMBOL, RPAREN);
}

void Case::print() {
   if (is_default) {
      append_colored(COLOR_KEYWORD, DEFAULT);
   }
   else {
      append_colored(COLOR_KEYWORD, CASE);
      append(' ');
      line += label;
   }
   append_colored(COLOR_SYMBOL, COLON);
   flush();
   indent += 3;
   Block::print();
   indent -= 3;
}

void Switch::print() {
   append_colored(COLOR_KEYWORD, SWITCH);
   append(' ');
   append_colored(COLOR_SYMBOL, LPAREN);
   cond->print();
   append_colored(COLOR_SYMBOL, RPAREN);
   append(' ');
   append_colored(COLOR_SYMBOL, LBRACE);
   flush();
   indent += 3;
   for (vector<Case*>::iterator i = cases.begin(); i != cases.end(); i++) {
      (*i)->print();
   }
   indent -= 3;
   append_colored(COLOR_SYMBOL, "}");
}

void Switch::rename(const string &oldname, const string &newname) {
   cond->rename(oldname, newname);
   for (vector<Case*>::iterator i = cases.begin(); i != cases.end(); i++) {
      (*i)->rename(oldname, newname);
   }
}

void Return::print() {
   append_colored(COLOR_KEYWORD, RETURN);
   if (expr) {
      append(' ');
      expr->print();
   }
}

void Return::rename(const string &oldname, const string &newname) {
   if (expr) {
      expr->rename(oldname, newname);
   }
}

AssignExpr::~AssignExpr() {
   delete lval;
   delete rval;
}

void AssignExpr::print() {
   lval->print();
   append(' ');
   append_colored(COLOR_SYMBOL, "=");
   append(' ');
   rval->print();
}

void AssignExpr::rename(const string &oldname, const string &newname) {
   dmsg("AssignExpr::rename from %s to %s\n", oldname.c_str(), newname.c_str());
   lval->rename(oldname, newname);
   rval->rename(oldname, newname);
}

void Ternary::print() {
   expr->print();
   append(' ');
   append_colored(COLOR_SYMBOL, "?");
   append(' ');
   _true->print();
   append(' ');
   append_colored(COLOR_SYMBOL, COLON);
   append(' ');
   _false->print();
}

void Ternary::rename(const string &oldname, const string &newname) {
   expr->rename(oldname, newname);
   _true->rename(oldname, newname);
   _false->rename(oldname, newname);
}

void Function::print() {
   prototype.print();
   flush();
   brace_print(block);
}

void Function::print(vector<string> *cfunc) {
   AstItem::cfunc = cfunc;
   line.clear();
   indent = 0;
   print();
}

void Function::rename(const string &oldname, const string &newname) {
   prototype.rename(oldname, newname);
   block.rename(oldname, newname);
}

List::const_iterator find_match(List::const_iterator &it, const string &sym, const string &open) {
   List::const_iterator res = it;
   while ((*res)->getContent() != sym || getAttributeValue(*res, "close") != open) {
      res++;
   }
   return res;
}

List::const_iterator find(List::const_iterator &it, const string &sym) {
   List::const_iterator res = it;
   while ((*res)->getContent() != sym) {
      res++;
   }
   return res;
}

static Type *type_handler(const Element *el) {
   //map the type name here
   return new Type(el->getContent());
}

static Return *return_handler(List::const_iterator &it, List::const_iterator &end) {
   Return *result = new Return();
   Expression *expr = expr_handler(it, end);
   EmptyExpr *ee = dynamic_cast<EmptyExpr*>(expr);
   if (ee) {
      delete ee;
      result->expr = NULL;
   }
   else {
      result->expr = expr;
   }
   return result;
}

static Statement *statement_handler(const Element *el) {
   static int scount = 0;
   dmsg("statement_handler in %d\n", scount++);
   Statement *result = NULL;
   Expression *lhs = NULL;
   const List &children = el->getChildren();
   List::const_iterator end = children.end();
   for (List::const_iterator it = children.begin(); it < end; it++) {
      const Element *child = get_child(it);
      if (is_keyword_color(child) && child->getContent() == BREAK) {
         return new BreakStatement();
      }
      switch (tag_map[child->getName()]) {
         case ast_tag_op: {
            //need to consume consecutive children at this level to form a statement
            switch (op_map[child->getContent()]) {
               case kw_return:
                  result = return_handler(++it, end);
                  dmsg("statement_handler out(1) %d\n", --scount);
                  return result;
               default:
                  dmsg("no op_map match for '%s' in statement\n", child->getContent().c_str());
                  lhs = expr_handler(it, end);
                  dmsg("no op_map match for '%s' in statement result: %s\n", child->getContent().c_str(), debug_print(lhs));
                  if (result) {
                     dmsg("oddly, result is '%s'\n", debug_print(result));
                  }
                  break;
            }
            break;
         }
         case ast_tag_label:
            result = new LabelStatement(child->getContent());
            dmsg("statement_handler out(2) %d - Label: %s\n", --scount, debug_print(result));
            return result;
         case ast_tag_syntax: {
            if (child->getContent() == GOTO) {
               GotoStatement *g = new GotoStatement();
               g->label = expr_handler(++it, end);
               dmsg("statement_handler out(3) %d\n", --scount);
               return g;
            }
            else {
               dmsg("no syntax match for '%s' in statement\n", child->getContent().c_str());
               dmsg("Trying to build an expression\n");
               Expression *expr = expr_handler(it, end);
               if (expr) {
                  dmsg("statement_handler out(4) %d\n", --scount);
                  return new ExprStatement(expr);
               }
            }
            break;
         }
         default:
            dmsg("no tag_map match for %s in statement, trying expression\n", child->getName().c_str());
            lhs = expr_handler(it, end);
            break;
      }
   }
   if (result == NULL) {
      dmsg("statement_handler is returning NULL\n");
      if (lhs != NULL) {
         result = new ExprStatement(lhs);
      }
      else {
         dmsg("statement_handler has no result\n");
      }
   }
   else {
      dmsg("returning from statement_handler -> %p\n", result);

   }
   dmsg("statement_handler out(0) %d - %s\n", --scount, debug_print(result));
   return result;
}

static VarDecl *vardecl_handler(const Element *el) {
   const List &children = el->getChildren();
   VarDecl *result = new VarDecl();
   List::const_iterator it;
   List::const_iterator end = children.end();
   for (it = children.begin(); result->type == NULL && it < end; it++) {
      const Element *child = get_child(it);
      switch (tag_map[child->getName()]) {
         case ast_tag_type:
            result->type = type_handler(child);
            break;
         default:
            break;
      }
   }
   if (result->type) {
      result->var = expr_handler(it, end);
      // find the name of the resulting variable, an transform any stack variable
      // names to IDA compatible names  xxStackNN -> var_NN
   }
   return result;
}

static void funcproto_handler(const Element *el, Function *f) {
   bool have_proto = false;
   bool have_name = false;
   const List &children = el->getChildren();
   for (List::const_iterator it = children.begin(); it < children.end(); it++) {
      const Element *child = get_child(it);
      if (have_proto && !have_name && is_keyword_color(child)) {
         f->prototype.keywords.push_back(child->getContent());
         continue;
      }
      switch (tag_map[child->getName()]) {
         case ast_tag_return_type:
            f->prototype.return_type = type_handler(find_child(child, "type"));
            have_proto = true;
            break;
         case ast_tag_syntax:
            break;
         case ast_tag_vardecl: {
            VarDecl *d = vardecl_handler(child);
            if (d) {
               f->prototype.parameters.push_back(d);
            }
            else {
               //error
            }
            break;
         }
         case ast_tag_funcname:
            f->prototype.name = child->getContent();
            have_name = true;
            break;
         default:
            break;
      }
   }
}

static CastExpr *cast_handler(List::const_iterator &it, List::const_iterator &end) {
   dmsg("Entering cast_handler\n");
   const Element *child = get_child(it);
   CastExpr *result = new CastExpr(child->getContent());  //map type name change here
   while (++it < end) {
      child = get_child(it);
      if (child->getName() == "op") {
         if (child->getContent() == "*") {
            result->deref++;
         }
         else {
            dmsg("cast_handler unknown op: %s\n", child->getContent().c_str());
         }
      }
      else if (child->getName() == "syntax") {
         if (child->getContent() == RPAREN) {
            dmsg("Leaving cast_handler (1) - %p\n", result);
            it--;
            return result;
         }
         else {
            dmsg("cast_handler unknown syntax: %s\n", child->getContent().c_str());
         }
      }
      else {
         dmsg("cast_handler unknown tag: %s\n", child->getName().c_str());
      }
   }
   dmsg("Leaving cast_handler (2) - %p\n", result);
   return result;
}

static Expression *expr_handler(List::const_iterator &it, List::const_iterator &end, bool in_paren) {
   static int ecount = 0;
   Expression *result = NULL;
   const string *open = NULL;
   ParenExpr *p = NULL;
   dmsg("expr_handler in %d\n", ecount++);
   for (; it < end; it++) {
      const Element *child = get_child(it);
      if (is_funcname_color(child)) {
         dmsg("expr_handler op building CallExpr(1)\n");
         CallExpr *call = new CallExpr(new FuncNameExpr(child->getContent()), expr_handler(++it, end));

         dmsg("expr_handler op built CallExpr - %s\n", debug_print(call));
         dmsg("expr_handler out(3) %d\n", --ecount);
         return call;
      }
      switch (tag_map[child->getName()]) {
         case ast_tag_variable:
            result = new NameExpr(child->getContent());
            break;
         case ast_tag_type: {
            CastExpr *cast = cast_handler(it, end);
            result = cast;
            dmsg("expr_handler out(1) %d\n", --ecount);
            return result;
         }
         case ast_tag_label:
            result = new LabelExpr(child->getContent());
            dmsg("expr_handler out(2) %d\n", --ecount);
            return result;
         case ast_tag_funcname: {
            dmsg("expr_handler tag building CallExpr(2)\n");
            CallExpr *call = new CallExpr(new FuncNameExpr(child->getContent()), expr_handler(++it, end));

            dmsg("expr_handler tag built CallExpr - %s\n", debug_print(call));
            dmsg("expr_handler out(3) %d\n", --ecount);
            return call;
         }
         case ast_tag_statement: {
            dmsg("expr_handler tag building statement\n");
            Statement *s = statement_handler(child);
            ExprStatement *e = dynamic_cast<ExprStatement*>(s);
            if (e) {
               //take ownership of the sub-expression;
               result = e->expr;
               e->expr = NULL;
               delete e;
            }
            else {
               dmsg("Expected ExprStatement but didn't get one\n");
               delete s;
            }
         }
         case ast_tag_syntax: {
            const string &op = child->getContent();
            if (is_const_color(child)) {
               dmsg("expr_handler syntax building LiteralExpr for %s\n", op.c_str());
               result = new LiteralExpr(op);
               dmsg("   %s\n", debug_print(result));
            }
            else if (unary_ops.find(op) != unary_ops.end() && result == NULL) {
               dmsg("expr_handler syntax building UnaryExpr for %s\n", op.c_str());
               result = new UnaryExpr(op, expr_handler(++it, end));
               dmsg("   %s\n", debug_print(result));
            }
            else if (binary_ops.find(op) != binary_ops.end() && result != NULL) {
               dmsg("expr_handler syntax building BinaryExpr for %s\n", op.c_str());
               result = new BinaryExpr(op, result, expr_handler(++it, end));
               dmsg("   %s\n", debug_print(result));
            }
            else {
               switch (ops[op]) {
                  case g_null:
                     dmsg("expr_handler syntax op is g_null for '%s'\n", op.c_str());
                     if (op.length() > 0) {
                        char *end;
                        uint64_t val = strtoull(op.c_str(), &end, 0);
                        if (*end == 0) {
                           result = new NumericExpr(op);
                        }
                        else {
                           result = new LiteralExpr(op);
                        }
                     }
                     break;
                  case g_lparen: {
                     //recurse into expr, we now have a parenthized expression
                     open = &getAttributeValue(child, "open");
                     dmsg("expr_handler syntax building ParenExpr for %s\n", open->c_str());
                     p = new ParenExpr(expr_handler(++it, end, true));
                     it++; //increment past the close )
                     dmsg("   ParenExpr(%s): %s\n", open->c_str(), debug_print(p));
                     CastExpr *c = dynamic_cast<CastExpr*>(p->inner);
                     if (c) {
                        result = new TypeCast(p, expr_handler(++it, end));
                        dmsg("   TypeCast(%s): %s\n", open->c_str(), debug_print(result));
                     }
                     else {
                        if (result != NULL) {
                           //This looks more like a fucntion call then
                           result = new CallExpr(result, p);
                           dmsg("   Looks like function call: %s\n", debug_print(result));
                        }
                        else {
                           result = p;
                        }
                     }
                     break;
                  }
                  case g_rparen: {
                     const string &close = getAttributeValue(child, "close");
                     dmsg("expr_handler rolling back rparen at level %d\n", ecount - 1);
                     it--;

                     dmsg("expr_handler terminating on rparen %s\n", close.c_str());
                     dmsg("expr_handler out(5) %d - %p - %s\n", --ecount, result, typeid(result).name());
                     return result;
                  }
                  case g_lbracket: {
                     //recurse into expr, we now have a parenthized expression
                     Expression *index = expr_handler(++it, end);
                     result = new ArrayExpr(result, index);
                     break;
                  }
                  case g_rbracket: {
                     // this is probably unmatched, so return what we have to caller
                     dmsg("expr_handler terminating on rbracket\n");
                     const string &close = getAttributeValue(child, "close");
                     dmsg("expr_handler out(6) %d - %p\n", --ecount, result);
                     return result;
                  }
                  case g_comma: {
                     Expression *rhs = expr_handler(++it, end);
                     result = new CommaExpr(result, rhs);
                     dmsg("expr_handler comma out(7) %d - %p\n", --ecount, result);
                     return result;
                  }
                  case g_semi: {
                     dmsg("expr_handler terminating on semicolon\n");
                     dmsg("expr_handler out(8) %d - %p\n", --ecount, result);
                     return result;
                  }
                  case g_assign: {
                     dmsg("expr_handler terminating on assign\n");
                     dmsg("expr_handler out(9) %d - %p\n", --ecount, result);
                     return result;
                  }
               }
            }
            break;
         }
         case ast_tag_op: {
            const string &op = child->getContent();
            if (unary_ops.find(op) != unary_ops.end() && result == NULL) {
               dmsg("expr_handler op building UnaryExpr\n");
               result = new UnaryExpr(op, expr_handler(++it, end));
               dmsg("expr_handler op built UnaryExpr(%p) for %s\n", result, op.c_str());
               dmsg("   %s\n", debug_print(result));
            }
            else if (binary_ops.find(op) != binary_ops.end() && result != NULL) {
               dmsg("expr_handler op building BinaryExpr\n");
               result = new BinaryExpr(op, result, expr_handler(++it, end));
               dmsg("expr_handler op building BinaryExpr(%p) for %s\n", result, op.c_str());
               dmsg("   %s\n", debug_print(result));
               dmsg("expr_handler out %d(10) - %p\n", --ecount, result);
               return result;
            }
            else {
               switch (ops[op]) {
                  case g_null:
                     dmsg("expr_handler op op is g_null\n");
                     break;
                  case g_assign: {
                     dmsg("expr_handler op building AssignExpr\n");
                     Expression *rhs = expr_handler(++it, end);
                     result = new AssignExpr(result, rhs);
                     dmsg("expr_handler op built AssignExpr(%p) - %s\n", result, debug_print(result));
                     dmsg("expr_handler out(11) %d\n", --ecount);
                     return result;
                  }
                  case g_comma: {
                     Expression *rhs = expr_handler(++it, end);
                     result = new CommaExpr(result, rhs);
                     dmsg("expr_handler out(12) %d\n", --ecount);
                     return result;
                  }
                  default:
                     dmsg("expr_handler no case for op/%s\n", op.c_str());
                     break;
               }
            }
            break;
         }
         default:
            dmsg("expr_handler unhandled tag_map: %s(%s)\n", child->getName().c_str(), child->getContent().c_str());
            break;
      }
      //it can be advanced in some of the functions called above
      if (it == end) {
         break;
      }
   }

   dmsg("expr_handler out(side loop) %d - %p\n", --ecount, result);
   if (result == NULL) {
      return new EmptyExpr();
   }
   else {
      dmsg("   returning: %s\n", debug_print(result));
   }
   return result;
}

static void conditional_common(ConditionalStatement *cs, List::const_iterator &it) {
   const Element *child;

   it = find(it, LPAREN);
   const string &open = getAttributeValue(*it, "open");
   it++;

   List::const_iterator end = find_match(it, RPAREN, open);

   cs->cond = expr_handler(it, end);

   it = ++end;  //resume after condition's close paren

   child = get_child(it);
   while (child->getName() != "block" && child->getName() != "statement") {
      it++;
      child = get_child(it);
   }
   if (child->getName() == "block") {
      block_handler(child, &cs->block);
   }
   else { //statement
      cs->block.push_back(statement_handler(child));
   }
}

static If *if_handler(List::const_iterator &it) {
   If *result = new If();
   dmsg("building new if\n");

   conditional_common(result, it);

   //don't try to handle else here
   //check for else in main handler

   return result;
}

static While *while_handler(List::const_iterator &it, List::const_iterator &end) {
   static int wcount = 0;
   While *result = new While();
   dmsg("building new while - %d\n", wcount++);

   //ghidra in its infinite wisdom does not place the body of
   //a while inside of a <block> tag, but MAYBE, a block enclose
   //everything from 'while(...) {...}'

   it = find(it, LPAREN);
   const string &open = getAttributeValue(*it, "open");
   it++;

   List::const_iterator cend = find_match(it, RPAREN, open);

   result->cond = expr_handler(it, cend);

   it = ++cend;  //resume after condition's close paren

   //let's hope they at least brace everything
   it = find(it, LBRACE);
   it++;

   //this is basically the same as a block_handler loop
   //without the benefit of knowing where the end of the child
   //list is
   while (it < end) {
      //we're not inside a block so we don't have a defined end
      //point for child iteration
      const Element *child = get_child(it);
      if (child->getContent() == "}") {
         //this is the only way to know we've reached the end at this level?
         break;
      }

      switch (tag_map[child->getName()]) {
         case ast_tag_label: {
            LabelStatement *label = new LabelStatement(child->getContent());
            result->push_back(label);
            break;
         }
         case ast_tag_block: {
            dmsg("while_handler::block\n");
            block_handler(child, &result->block);
            break;
         }
         case ast_tag_op: { //this will be a compound statement??
            dmsg("while_handler::op\n");
            //need to consume consecutive children at this level to form a statement
            switch (op_map[child->getContent()]) {
               case kw_if: {
                  dmsg("while_handler::kw_if\n");
                  If *_if = if_handler(++it);
                  if (_if) {
                     result->push_back(_if);
                  }
                  else {
                  }
                  break;
               }
               case kw_switch: {
                  dmsg("while_handler::kw_switch\n");
                  Switch *sw = switch_handler(++it);
                  if (sw) {
                     result->push_back(sw);
                  }
                  else {
                  }
                  break;
               }
               case kw_while: {
                  //I hope this can never happend without first being in a nested <block>
                  //otherwise the end iterator being passed in below will be the end of the
                  //outer while, not the inner while we are about to parse.
                  dmsg("while_handler::kw_while\n");
                  While *w = while_handler(++it, end);
                  if (w) {
                     result->push_back(w);
                  }
                  else {
                  }
                  break;
               }
               case kw_return:
//                  block->block.push_back(return_handler(it));
                  break;
               default:
                  dmsg("while_handler no op_map match for %s\n", child->getContent().c_str());
                  break;
            }
            break;
         }
         case ast_tag_statement: {
            dmsg("while_handler::statement\n");
            Statement *s = statement_handler(child);
            if (s) {
               result->push_back(s);
            }
            else {
               //error
            }
            break;
         }
         case ast_tag_syntax:
            if (child->getContent() == ELSE) {
               If *_if = dynamic_cast<If*>(result->back());
               if (_if) {
                  dmsg("while_handler appending else to previous if\n");
                  Else *_else = else_handler(it);
                  if (_else) {
                     _if->_else = _else;
                  }
                  else {
                  }
               }
               else {
                  //error, we don't have an if statement to pair with the else
                  dmsg("Seeing else, bu previous is %s\n", typeid(result->back()).name());
               }
            }
            else if (child->getContent() == DO) {
               dmsg("while_handler::statement\n");
               Statement *s = do_handler(it);
               if (s) {
                  result->push_back(s);
               }
               else {
                  //error
               }
            }
            break;
         default:
            break;
      }
      it++;
   }
   dmsg("while_handler out %d\n", --wcount);
   return result;
}

static Case *build_case(List::const_iterator &it, bool is_default = false) {
   Case *result = new Case(is_default);

   if (!is_default) {
      while (!is_const_color(*it)) {
         it++;
      }
      result->label = (*it)->getContent();
      dmsg("case label is %s\n", result->label.c_str());

      it++;
   }
   const Element *child = get_child(it);
   while (child->getName() != "block" && child->getName() != "statement") {
      it++;
      child = get_child(it);
   }
   if (child->getName() == "block") {
      block_handler(child, result);
   }
   else { //statement
      result->block.push_back(statement_handler(child));
   }
   it++;

   return result;
}

static Switch *switch_handler(List::const_iterator &it) {
   Switch *result = new Switch();
   const Element *child;
   dmsg("building new switch\n");

   it = find(it, LPAREN);
   const string &open = getAttributeValue(*it, "open");
   it++;

   List::const_iterator end = find_match(it, RPAREN, open);

   result->cond = expr_handler(it, end);

   it = ++end;  //resume after condition's close paren

   while (true) {
      child = get_child(it);
      if (child->getContent() == "}") {
         break;
      }
      else if (child->getContent() == CASE) {
         result->cases.push_back(build_case(it));
      }
      else if (child->getContent() == DEFAULT) {
         result->cases.push_back(build_case(it, true));
         result->cases.back()->is_default = true;
      }
      it++;
   }
   return result;
}

static DoWhile *do_handler(List::const_iterator &it) {
   DoWhile *result = new DoWhile();
   const Element *child;
   dmsg("building new do/while\n");

   child = get_child(it);
   while (child->getName() != "block" && child->getName() != "statement") {
      it++;
      child = get_child(it);
   }
   if (child->getName() == "block") {
      block_handler(child, &result->block);
   }
   else { //statement
      result->block.push_back(statement_handler(child));
   }

   //find the condition
   while (true) {
      child = get_child(it);
      if (child->getContent() == LPAREN) {
         break;
      }
      it++;
   }
   const string &open = getAttributeValue(child, "open");
   it++;

   List::const_iterator end = find_match(it, RPAREN, open);

   result->cond = expr_handler(it, end);

   it = ++end;  //resume after condition's close paren

   return result;
}

static Else *else_handler(List::const_iterator &it) {
   const Element *child = get_child(it);
   Else *result = new Else();
   while (child->getName() != "block" && child->getName() != "statement") {
      it++;
      child = get_child(it);
   }
   if (child->getName() == "block") {
      block_handler(child, &result->block);
   }
   else { //statement
      result->block.push_back(statement_handler(child));
   }
   dmsg("built an else - %p\n", result);
   return result;
}

static void block_handler(const Element *el, Block *block) {
   static int bcount = 0;
   dmsg("block_handler in %d\n", bcount++);
   const List &children = el->getChildren();
   List::const_iterator it = children.begin();
   List::const_iterator end = children.end();
   while (it < end) {
      const Element *child = get_child(it);
      switch (tag_map[child->getName()]) {
         case ast_tag_label: {
            LabelStatement *label = new LabelStatement(child->getContent());
            block->push_back(label);
            break;
         }
         case ast_tag_block: {
            dmsg("block_handler::block\n");
            block_handler(child, block);
            break;
         }
         case ast_tag_op: { //this will be a compound statement??
            dmsg("block_handler::op\n");
            //need to consume consecutive children at this level to form a statement
            switch (op_map[child->getContent()]) {
               case kw_if: {
                  dmsg("block_handler::kw_if\n");
                  If *_if = if_handler(++it);
                  if (_if) {
                     block->push_back(_if);
                  }
                  else {
                  }
                  break;
               }
               case kw_switch: {
                  dmsg("block_handler::kw_switch\n");
                  Switch *sw = switch_handler(++it);
                  if (sw) {
                     block->push_back(sw);
                  }
                  else {
                  }
                  break;
               }
               case kw_while: {
                  dmsg("block_handler::kw_while\n");
                  While *w = while_handler(++it, end);
                  if (w) {
                     block->push_back(w);
                  }
                  else {
                  }
                  break;
               }
               case kw_return:
//                  block->block.push_back(return_handler(it));
                  break;
               default:
                  dmsg("no op_map match for %s\n", child->getContent().c_str());
                  break;
            }
            break;
         }
         case ast_tag_statement: {
            dmsg("block_handler::statement\n");
            Statement *s = statement_handler(child);
            if (s) {
               block->push_back(s);
            }
            else {
               //error
            }
            break;
         }
         case ast_tag_syntax:
            if (child->getContent() == ELSE) {
               If *_if = dynamic_cast<If*>(block->back());
               if (_if) {
                  dmsg("appending else to previous if\n");
                  Else *_else = else_handler(it);
                  if (_else) {
                     _if->_else = _else;
                  }
                  else {
                  }
               }
               else {
                  //error, we don't have an if statement to pair with the else
                  dmsg("Seeing else, bu previous is %s\n", typeid(block->back()).name());
               }
            }
            else if (child->getContent() == DO) {
               dmsg("block_handler::statement\n");
               Statement *s = do_handler(it);
               if (s) {
                  block->push_back(s);
               }
               else {
                  //error
               }
            }
            break;
         default:
            break;
      }
      //it can be advance in some of the functions called above
      if (it == end) {
         break;
      }
      it++;
   }
   dmsg("block_handler out %d\n", --bcount);
}

void init_maps(void) {
   static bool maps_are_init = false;
   if (!maps_are_init) {
      maps_are_init = true;

      tag_map["syntax"] = ast_tag_syntax;
      tag_map["break"] = ast_tag_break;
      tag_map["funcproto"] = ast_tag_funcproto;
      tag_map["vardecl"] = ast_tag_vardecl;
      tag_map["return_type"] = ast_tag_return_type;
      tag_map["type"] = ast_tag_type;
      tag_map["variable"] = ast_tag_variable;
      tag_map["block"] = ast_tag_block;
      tag_map["statement"] = ast_tag_statement;
      tag_map["funcname"] = ast_tag_funcname;
      tag_map["op"] = ast_tag_op;
      tag_map["label"] = ast_tag_label;

      op_map[IF] = kw_if;
      op_map[SWITCH] = kw_switch;
      op_map[WHILE] = kw_while;
      op_map[RETURN] = kw_return;
      op_map["="] = kw_assign;

      ops[LBRACE] = g_lbrace;
      ops[RBRACE] = g_rbrace;
      ops[LPAREN] = g_lparen;
      ops[RPAREN] = g_rparen;
      ops[LBRACKET] = g_lbracket;
      ops[RBRACKET] = g_rbracket;
      ops["&"] = g_and;
      ops["|"] = g_or;
      ops["^"] = g_xor;
      ops["!"] = g_not;
      ops["~"] = g_bnot;
      ops["||"] = g_logical_or;
      ops["&&"] = g_logical_and;
      ops[COMMA] = g_comma;
      ops[SEMICOLON] = g_semi;
      ops["<<"] = g_lshift;
      ops[">>"] = g_rshift;
      ops["<"] = g_lt;
      ops["<="] = g_lte;
      ops[">"] = g_gt;
      ops[">="] = g_gte;
      ops["="] = g_assign;
      ops["=="] = g_eq;
      ops["!="] = g_ne;
      ops["+"] = g_plus;
      ops["-"] = g_minus;
      ops["%"] = g_mod;
      ops["/"] = g_div;
      ops["*"] = g_star;
      ops["+="] = g_plus_eq;
      ops["-="] = g_minus_eq;
      ops["*="] = g_star_eq;
      ops["/="] = g_div_eq;
      ops["%="] = g_mod_eq;
      ops["&="] = g_and_eq;
      ops["|="] = g_or_eq;
      ops["^="] = g_xor_eq;
      ops["<<="] = g_lshift_eq;
      ops[">>="] = g_rshift_eq;
      ops["++"] = g_plusplus;
      ops["--"] = g_minusminus;
      ops["?"] = g_qmark;
      ops[COLON] = g_colon;

      binary_ops.insert("&");
      binary_ops.insert("|");
      binary_ops.insert("^");
      binary_ops.insert("||");
      binary_ops.insert("&&");
      binary_ops.insert("<<");
      binary_ops.insert(">>");
      binary_ops.insert("<");
      binary_ops.insert("<=");
      binary_ops.insert(">");
      binary_ops.insert(">=");
      binary_ops.insert("==");
      binary_ops.insert("!=");
      binary_ops.insert("+");
      binary_ops.insert("-");
      binary_ops.insert("%");
      binary_ops.insert("/");
      binary_ops.insert("*");

      unary_ops.insert("++");
      unary_ops.insert("--");
      unary_ops.insert("++ ");
      unary_ops.insert("-- ");
      unary_ops.insert("-");
      unary_ops.insert("!");
      unary_ops.insert("~");
      unary_ops.insert("*");
      unary_ops.insert("&");

      reserved.insert(WHILE);
      reserved.insert(DO);
      reserved.insert(IF);
      reserved.insert(ELSE);
      reserved.insert(BREAK);
      reserved.insert(DEFAULT);
      reserved.insert(SWITCH);
      reserved.insert(CASE);
      reserved.insert(GOTO);
      reserved.insert(RETURN);
      reserved.insert("for");
      
      reserved.insert("int");
      reserved.insert("bool");
      reserved.insert("char");
      reserved.insert("short");
      reserved.insert("long");
      reserved.insert("signed");
      reserved.insert("unsigned");
      reserved.insert("float");
      reserved.insert("double");
      reserved.insert("void");
      reserved.insert("NULL");
   }
}

bool is_reserved(const string &word) {
   return reserved.find(word) != reserved.end();
}

Function *func_from_xml(Element *func) {
   init_maps();
   int num_decls = 0;
   int num_blocks = 0;
   if (func->getName() != "function") {
      return NULL;
   }
   Function *result = new Function();
   bool have_proto = false;
   const List &children = func->getChildren();
   for (List::const_iterator it = children.begin(); it < children.end(); it++) {
      const Element *child = get_child(it);
      if (!have_proto && child->getName() != "funcproto") {
         continue;
      }
      have_proto = true;
      switch (tag_map[child->getName()]) {
         case ast_tag_funcproto:
            funcproto_handler(child, result);
            break;
         case ast_tag_syntax:
            break;
         case ast_tag_vardecl: {
            Statement *s = vardecl_handler(child);
            if (s) {
               result->block.push_back(s);
               num_decls++;
            }
            else {
               //error
            }
            break;
         }
         case ast_tag_block:
            if (num_decls && !num_blocks) {
               result->block.push_back(new EmptyStatement());
            }
            block_handler(child, &result->block);
            num_blocks++;
            break;
         default:
            break;
      }
   }
   return result;
}
