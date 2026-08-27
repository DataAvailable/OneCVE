//===- SaberCheckerAPI.cpp -- API for checkers-------------------------------//
//
//                     SVF: Static Value-Flow Analysis
//
// Copyright (C) <2013->  <Yulei Sui>
//

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
//===----------------------------------------------------------------------===//

/*
 * SaberCheckerAPI.cpp
 *
 *  Created on: Apr 23, 2014
 *      Author: Yulei Sui
 */
#include "SABER/SaberCheckerAPI.h"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <stdio.h>

using namespace std;
using namespace SVF;

SaberCheckerAPI* SaberCheckerAPI::ckAPI = nullptr;

namespace
{

/// string and type pair
struct ei_pair
{
    const char *n;
    SaberCheckerAPI::CHECKER_TYPE t;
};

} // End anonymous namespace

static string trimAPIConfigToken(const string& token)
{
    string::size_type begin = 0;
    string::size_type end = token.size();
    while(begin < end && !isalnum(static_cast<unsigned char>(token[begin])) && token[begin] != '_')
        ++begin;
    while(end > begin && !isalnum(static_cast<unsigned char>(token[end - 1])) && token[end - 1] != '_')
        --end;
    return token.substr(begin, end - begin);
}

static string normalizeAPIConfigToken(string token)
{
    transform(token.begin(), token.end(), token.begin(),
              [](unsigned char ch) { return static_cast<char>(tolower(ch)); });
    return token;
}

static bool parseCheckerTypeToken(const string& token, SaberCheckerAPI::CHECKER_TYPE& type)
{
    const string normalized = normalizeAPIConfigToken(token);
    if(normalized == "ck_alloc" || normalized == "alloc" ||
            normalized == "allocator" || normalized == "malloc")
    {
        type = SaberCheckerAPI::CK_ALLOC;
        return true;
    }
    if(normalized == "ck_free" || normalized == "free" ||
            normalized == "releaser" || normalized == "destroyer" ||
            normalized == "dealloc" || normalized == "deallocator")
    {
        type = SaberCheckerAPI::CK_FREE;
        return true;
    }
    if(normalized == "ck_fopen" || normalized == "fopen" ||
            normalized == "fileopen" || normalized == "file_open")
    {
        type = SaberCheckerAPI::CK_FOPEN;
        return true;
    }
    if(normalized == "ck_fclose" || normalized == "fclose" ||
            normalized == "fileclose" || normalized == "file_close")
    {
        type = SaberCheckerAPI::CK_FCLOSE;
        return true;
    }
    return false;
}

//Each (name, type) pair will be inserted into the map.
//All entries of the same type must occur together (for error detection).
static const ei_pair ei_pairs[]=
{
    {"alloc", SaberCheckerAPI::CK_ALLOC},
    {"alloc_check", SaberCheckerAPI::CK_ALLOC},
    {"alloc_clear", SaberCheckerAPI::CK_ALLOC},
    {"calloc", SaberCheckerAPI::CK_ALLOC},
    {"jpeg_alloc_huff_table", SaberCheckerAPI::CK_ALLOC},
    {"jpeg_alloc_quant_table", SaberCheckerAPI::CK_ALLOC},
    {"lalloc", SaberCheckerAPI::CK_ALLOC},
    {"lalloc_clear", SaberCheckerAPI::CK_ALLOC},
    {"malloc", SaberCheckerAPI::CK_ALLOC},
    {"nhalloc", SaberCheckerAPI::CK_ALLOC},
    {"oballoc", SaberCheckerAPI::CK_ALLOC},
    {"permalloc", SaberCheckerAPI::CK_ALLOC},
    {"png_create_info_struct", SaberCheckerAPI::CK_ALLOC},
    {"png_create_write_struct", SaberCheckerAPI::CK_ALLOC},
    {"safe_calloc", SaberCheckerAPI::CK_ALLOC},
    {"safe_malloc", SaberCheckerAPI::CK_ALLOC},
    {"safecalloc", SaberCheckerAPI::CK_ALLOC},
    {"safemalloc", SaberCheckerAPI::CK_ALLOC},
    {"safexcalloc", SaberCheckerAPI::CK_ALLOC},
    {"safexmalloc", SaberCheckerAPI::CK_ALLOC},
    {"savealloc", SaberCheckerAPI::CK_ALLOC},
    {"xalloc", SaberCheckerAPI::CK_ALLOC},
    {"xcalloc", SaberCheckerAPI::CK_ALLOC},
    {"xmalloc", SaberCheckerAPI::CK_ALLOC},
    {"SSL_CTX_new", SaberCheckerAPI::CK_ALLOC},
    {"SSL_new", SaberCheckerAPI::CK_ALLOC},
    {"VOS_MemAlloc", SaberCheckerAPI::CK_ALLOC},
    /* NSPA_AUTO_SCREEN_CK_ALLOC_BEGIN */
    /* NSPA: screen project-specific CK_ALLOC entries */
    {"AddPerp", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.8, src/canvas.c
    {"CatExtra", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.85, src/fileio.c
    {"CreateLayout", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.85, src/layout.c
    {"CreateTransTable", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.5, src/termcap.c
    {"FindKtab", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.8, src/process.c
    {"GrowBitfield", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.75, src/acls.c
    {"InitOverlayPage", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.55, src/layer.c
    {"InputSu", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.85, src/process.c
    {"MFixLine", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.6, src/ansi.c
    {"MakeDisplay", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.85, src/display.c
    {"MakeWindow", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.6, src/window.c
    {"ReadFile", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.97, src/fileio.c
    {"SaveAction", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.8, src/process.c
    {"SaveArgs", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.92, src/process.c
    {"SaveStr", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.9, src/misc.c
    {"SaveStrn", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.9, src/misc.c
    {"UserAdd", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.9, src/acls.c
    {"glist_add_row", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.8, src/list_generic.c
    {"logfopen", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.9, src/logfile.c
    {"realloc", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.85, src/tests/mallocmock.c
    {"recode_mline", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.8, src/encoding.c
    {"wmb_create", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.97, src/winmsgbuf.c
    {"wmb_expand", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.7, src/winmsgbuf.c
    {"wmbc_create", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.95, src/winmsgbuf.c
    {"xrealloc", SaberCheckerAPI::CK_ALLOC},  // allocator, conf=0.9, src/resize.c
    /* NSPA_AUTO_SCREEN_CK_ALLOC_END */





































    {"VOS_MemFree", SaberCheckerAPI::CK_FREE},
    {"cfree", SaberCheckerAPI::CK_FREE},
    {"free", SaberCheckerAPI::CK_FREE},
    {"free_all_mem", SaberCheckerAPI::CK_FREE},
    {"freeaddrinfo", SaberCheckerAPI::CK_FREE},
    {"gcry_mpi_release", SaberCheckerAPI::CK_FREE},
    {"gcry_sexp_release", SaberCheckerAPI::CK_FREE},
    {"globfree", SaberCheckerAPI::CK_FREE},
    {"nhfree", SaberCheckerAPI::CK_FREE},
    {"obstack_free", SaberCheckerAPI::CK_FREE},
    {"safe_cfree", SaberCheckerAPI::CK_FREE},
    {"safe_free", SaberCheckerAPI::CK_FREE},
    {"safefree", SaberCheckerAPI::CK_FREE},
    {"safexfree", SaberCheckerAPI::CK_FREE},
    {"sm_free", SaberCheckerAPI::CK_FREE},
    {"vim_free", SaberCheckerAPI::CK_FREE},
    {"xfree", SaberCheckerAPI::CK_FREE},
    {"SSL_CTX_free", SaberCheckerAPI::CK_FREE},
    {"SSL_free", SaberCheckerAPI::CK_FREE},
    {"XFree", SaberCheckerAPI::CK_FREE},
    /* NSPA_AUTO_SCREEN_CK_FREE_BEGIN */
    /* NSPA: screen project-specific CK_FREE entries */
    {"ClearAction", SaberCheckerAPI::CK_FREE},  // releaser, conf=0.7, src/process.c
    {"FreeAltScreen", SaberCheckerAPI::CK_FREE},  // releaser, conf=0.8, src/resize.c
    {"FreeCanvas", SaberCheckerAPI::CK_FREE},  // destroyer, conf=0.8, src/canvas.c
    {"FreeLayoutCv", SaberCheckerAPI::CK_FREE},  // releaser, conf=0.7, src/layout.c
    {"FreeMline", SaberCheckerAPI::CK_FREE},  // releaser, conf=0.85, src/resize.c
    {"FreePaster", SaberCheckerAPI::CK_FREE},  // releaser, conf=0.6, src/mark.c
    {"FreePerp", SaberCheckerAPI::CK_FREE},  // releaser, conf=0.65, src/canvas.c
    {"FreePseudowin", SaberCheckerAPI::CK_FREE},  // releaser, conf=0.55, src/window.c
    {"FreeWindow", SaberCheckerAPI::CK_FREE},  // destroyer, conf=0.7, src/window.c
    {"FreeWindowAcl", SaberCheckerAPI::CK_FREE},  // releaser, conf=0.85, src/acls.c
    {"LayerCleanupMemory", SaberCheckerAPI::CK_FREE},  // releaser, conf=0.75, src/layer.c
    {"RemoveLayout", SaberCheckerAPI::CK_FREE},  // destroyer, conf=0.65, src/layout.c
    {"UserDel", SaberCheckerAPI::CK_FREE},  // destroyer, conf=0.85, src/acls.c
    {"UserFreeCopyBuffer", SaberCheckerAPI::CK_FREE},  // releaser, conf=0.85, src/acls.c
    {"gl_Window_free", SaberCheckerAPI::CK_FREE},  // releaser, conf=0.6, src/list_window.c
    {"gl_Window_remove", SaberCheckerAPI::CK_FREE},  // releaser, conf=0.6, src/list_window.c
    {"glist_remove_rows", SaberCheckerAPI::CK_FREE},  // releaser, conf=0.6, src/list_generic.c
    {"logfclose", SaberCheckerAPI::CK_FREE},  // destroyer, conf=0.7, src/logfile.c
    {"wmb_free", SaberCheckerAPI::CK_FREE},  // releaser, conf=0.6, src/winmsgbuf.c
    {"wmbc_free", SaberCheckerAPI::CK_FREE},  // releaser, conf=0.9, src/winmsgbuf.c
    /* NSPA_AUTO_SCREEN_CK_FREE_END */





































    {"fopen", SaberCheckerAPI::CK_FOPEN},
    {"\01_fopen", SaberCheckerAPI::CK_FOPEN},
    {"\01fopen64", SaberCheckerAPI::CK_FOPEN},
    {"\01readdir64", SaberCheckerAPI::CK_FOPEN},
    {"\01tmpfile64", SaberCheckerAPI::CK_FOPEN},
    {"fopen64", SaberCheckerAPI::CK_FOPEN},
    {"XOpenDisplay", SaberCheckerAPI::CK_FOPEN},
    {"XtOpenDisplay", SaberCheckerAPI::CK_FOPEN},
    {"fopencookie", SaberCheckerAPI::CK_FOPEN},
    {"popen", SaberCheckerAPI::CK_FOPEN},
    {"readdir", SaberCheckerAPI::CK_FOPEN},
    {"readdir64", SaberCheckerAPI::CK_FOPEN},
    {"gzdopen", SaberCheckerAPI::CK_FOPEN},
    {"iconv_open", SaberCheckerAPI::CK_FOPEN},
    {"tmpfile", SaberCheckerAPI::CK_FOPEN},
    {"tmpfile64", SaberCheckerAPI::CK_FOPEN},
    {"BIO_new_socket", SaberCheckerAPI::CK_FOPEN},
    {"gcry_md_open", SaberCheckerAPI::CK_FOPEN},
    {"gcry_cipher_open", SaberCheckerAPI::CK_FOPEN},


    {"fclose", SaberCheckerAPI::CK_FCLOSE},
    {"XCloseDisplay", SaberCheckerAPI::CK_FCLOSE},
    {"XtCloseDisplay", SaberCheckerAPI::CK_FCLOSE},
    {"__res_nclose", SaberCheckerAPI::CK_FCLOSE},
    {"pclose", SaberCheckerAPI::CK_FCLOSE},
    {"closedir", SaberCheckerAPI::CK_FCLOSE},
    {"dlclose", SaberCheckerAPI::CK_FCLOSE},
    {"gzclose", SaberCheckerAPI::CK_FCLOSE},
    {"iconv_close", SaberCheckerAPI::CK_FCLOSE},
    {"gcry_md_close", SaberCheckerAPI::CK_FCLOSE},
    {"gcry_cipher_close", SaberCheckerAPI::CK_FCLOSE},

    //This must be the last entry.
    {0, SaberCheckerAPI::CK_DUMMY}

};


/*!
 * initialize the map
 */
void SaberCheckerAPI::init()
{
    set<CHECKER_TYPE> t_seen;
    CHECKER_TYPE prev_t= CK_DUMMY;
    t_seen.insert(CK_DUMMY);
    for(const ei_pair *p= ei_pairs; p->n; ++p)
    {
        if(p->t != prev_t)
        {
            //This will detect if you move an entry to another block
            //  but forget to change the type.
            if(t_seen.count(p->t))
            {
                fputs(p->n, stderr);
                putc('\n', stderr);
                assert(!"ei_pairs not grouped by type");
            }
            t_seen.insert(p->t);
            prev_t= p->t;
        }
        if(tdAPIMap.count(p->n))
        {
            fputs(p->n, stderr);
            putc('\n', stderr);
            assert(!"duplicate name in ei_pairs");
        }
        tdAPIMap[p->n]= p->t;
    }
}

void SaberCheckerAPI::addCustomAPI(const string& funcName, CHECKER_TYPE type)
{
    if(funcName.empty() || type == CK_DUMMY)
        return;
    tdAPIMap[funcName] = type;
}

bool SaberCheckerAPI::loadCustomAPIsFromFile(const string& filename)
{
    ifstream input(filename.c_str());
    if(!input)
    {
        fprintf(stderr, "Cannot open custom API config file: %s\n", filename.c_str());
        return false;
    }

    string line;
    unsigned lineNo = 0;
    while(getline(input, line))
    {
        ++lineNo;

        string::size_type hash = line.find('#');
        if(hash != string::npos)
            line.erase(hash);
        string::size_type slash = line.find("//");
        if(slash != string::npos)
            line.erase(slash);

        for(char& ch : line)
        {
            if(ch == ':' || ch == '=' || ch == ',' || ch == ';' ||
                    ch == '[' || ch == ']' || ch == '{' || ch == '}' ||
                    ch == '(' || ch == ')' || ch == '"' || ch == '\'' ||
                    isspace(static_cast<unsigned char>(ch)))
            {
                ch = ' ';
            }
        }

        vector<string> tokens;
        string token;
        stringstream stream(line);
        while(stream >> token)
        {
            token = trimAPIConfigToken(token);
            if(!token.empty())
                tokens.push_back(token);
        }
        if(tokens.empty())
            continue;

        CHECKER_TYPE type = CK_DUMMY;
        size_t typeIndex = tokens.size();
        for(size_t i = 0; i < tokens.size(); ++i)
        {
            if(parseCheckerTypeToken(tokens[i], type))
            {
                typeIndex = i;
                break;
            }
        }

        if(type == CK_DUMMY)
        {
            fprintf(stderr, "Ignore custom API config line %u without checker type.\n", lineNo);
            continue;
        }

        for(size_t i = 0; i < tokens.size(); ++i)
        {
            if(i == typeIndex)
                continue;
            const string normalized = normalizeAPIConfigToken(tokens[i]);
            if(normalized == "name" || normalized == "names" ||
                    normalized == "function" || normalized == "functions" ||
                    normalized == "category" || normalized == "checker" ||
                    normalized == "checker_type" || normalized == "type")
            {
                continue;
            }
            addCustomAPI(tokens[i], type);
        }
    }

    return true;
}


