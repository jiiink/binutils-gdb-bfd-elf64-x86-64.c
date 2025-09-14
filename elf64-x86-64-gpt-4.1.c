/* X86-64 specific support for ELF
   Copyright (C) 2000-2025 Free Software Foundation, Inc.
   Contributed by Jan Hubicka <jh@suse.cz>.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "elfxx-x86.h"
#include "dwarf2.h"
#include "libiberty.h"
#include "sframe.h"

#include "opcode/i386.h"

#ifdef CORE_HEADER
#include <stdarg.h>
#include CORE_HEADER
#endif

/* In case we're on a 32-bit machine, construct a 64-bit "-1" value.  */
#define MINUS_ONE (~ (bfd_vma) 0)

/* Since both 32-bit and 64-bit x86-64 encode relocation type in the
   identical manner, we use ELF32_R_TYPE instead of ELF64_R_TYPE to get
   relocation type.  We also use ELF_ST_TYPE instead of ELF64_ST_TYPE
   since they are the same.  */

/* The relocation "howto" table.  Order of fields:
   type, rightshift, size, bitsize, pc_relative, bitpos, complain_on_overflow,
   special_function, name, partial_inplace, src_mask, dst_mask, pcrel_offset.  */
static reloc_howto_type x86_64_elf_howto_table[] =
{
  HOWTO(R_X86_64_NONE, 0, 0, 0, false, 0, complain_overflow_dont,
	bfd_elf_generic_reloc, "R_X86_64_NONE",	false, 0, 0x00000000,
	false),
  HOWTO(R_X86_64_64, 0, 8, 64, false, 0, complain_overflow_dont,
	bfd_elf_generic_reloc, "R_X86_64_64", false, 0, MINUS_ONE,
	false),
  HOWTO(R_X86_64_PC32, 0, 4, 32, true, 0, complain_overflow_signed,
	bfd_elf_generic_reloc, "R_X86_64_PC32", false, 0, 0xffffffff,
	true),
  HOWTO(R_X86_64_GOT32, 0, 4, 32, false, 0, complain_overflow_signed,
	bfd_elf_generic_reloc, "R_X86_64_GOT32", false, 0, 0xffffffff,
	false),
  HOWTO(R_X86_64_PLT32, 0, 4, 32, true, 0, complain_overflow_signed,
	bfd_elf_generic_reloc, "R_X86_64_PLT32", false, 0, 0xffffffff,
	true),
  HOWTO(R_X86_64_COPY, 0, 4, 32, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_X86_64_COPY", false, 0, 0xffffffff,
	false),
  HOWTO(R_X86_64_GLOB_DAT, 0, 8, 64, false, 0, complain_overflow_dont,
	bfd_elf_generic_reloc, "R_X86_64_GLOB_DAT", false, 0, MINUS_ONE,
	false),
  HOWTO(R_X86_64_JUMP_SLOT, 0, 8, 64, false, 0, complain_overflow_dont,
	bfd_elf_generic_reloc, "R_X86_64_JUMP_SLOT", false, 0, MINUS_ONE,
	false),
  HOWTO(R_X86_64_RELATIVE, 0, 8, 64, false, 0, complain_overflow_dont,
	bfd_elf_generic_reloc, "R_X86_64_RELATIVE", false, 0, MINUS_ONE,
	false),
  HOWTO(R_X86_64_GOTPCREL, 0, 4, 32, true, 0, complain_overflow_signed,
	bfd_elf_generic_reloc, "R_X86_64_GOTPCREL", false, 0, 0xffffffff,
	true),
  HOWTO(R_X86_64_32, 0, 4, 32, false, 0, complain_overflow_unsigned,
	bfd_elf_generic_reloc, "R_X86_64_32", false, 0, 0xffffffff,
	false),
  HOWTO(R_X86_64_32S, 0, 4, 32, false, 0, complain_overflow_signed,
	bfd_elf_generic_reloc, "R_X86_64_32S", false, 0, 0xffffffff,
	false),
  HOWTO(R_X86_64_16, 0, 2, 16, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_X86_64_16", false, 0, 0xffff, false),
  HOWTO(R_X86_64_PC16, 0, 2, 16, true, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_X86_64_PC16", false, 0, 0xffff, true),
  HOWTO(R_X86_64_8, 0, 1, 8, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_X86_64_8", false, 0, 0xff, false),
  HOWTO(R_X86_64_PC8, 0, 1, 8, true, 0, complain_overflow_signed,
	bfd_elf_generic_reloc, "R_X86_64_PC8", false, 0, 0xff, true),
  HOWTO(R_X86_64_DTPMOD64, 0, 8, 64, false, 0, complain_overflow_dont,
	bfd_elf_generic_reloc, "R_X86_64_DTPMOD64", false, 0, MINUS_ONE,
	false),
  HOWTO(R_X86_64_DTPOFF64, 0, 8, 64, false, 0, complain_overflow_dont,
	bfd_elf_generic_reloc, "R_X86_64_DTPOFF64", false, 0, MINUS_ONE,
	false),
  HOWTO(R_X86_64_TPOFF64, 0, 8, 64, false, 0, complain_overflow_dont,
	bfd_elf_generic_reloc, "R_X86_64_TPOFF64", false, 0, MINUS_ONE,
	false),
  HOWTO(R_X86_64_TLSGD, 0, 4, 32, true, 0, complain_overflow_signed,
	bfd_elf_generic_reloc, "R_X86_64_TLSGD", false, 0, 0xffffffff,
	true),
  HOWTO(R_X86_64_TLSLD, 0, 4, 32, true, 0, complain_overflow_signed,
	bfd_elf_generic_reloc, "R_X86_64_TLSLD", false, 0, 0xffffffff,
	true),
  HOWTO(R_X86_64_DTPOFF32, 0, 4, 32, false, 0, complain_overflow_signed,
	bfd_elf_generic_reloc, "R_X86_64_DTPOFF32", false, 0, 0xffffffff,
	false),
  HOWTO(R_X86_64_GOTTPOFF, 0, 4, 32, true, 0, complain_overflow_signed,
	bfd_elf_generic_reloc, "R_X86_64_GOTTPOFF", false, 0, 	0xffffffff,
	true),
  HOWTO(R_X86_64_TPOFF32, 0, 4, 32, false, 0, complain_overflow_signed,
	bfd_elf_generic_reloc, "R_X86_64_TPOFF32", false, 0, 0xffffffff,
	false),
  HOWTO(R_X86_64_PC64, 0, 8, 64, true, 0, complain_overflow_dont,
	bfd_elf_generic_reloc, "R_X86_64_PC64", false, 0, MINUS_ONE,
	true),
  HOWTO(R_X86_64_GOTOFF64, 0, 8, 64, false, 0, complain_overflow_dont,
	bfd_elf_generic_reloc, "R_X86_64_GOTOFF64", false, 0, MINUS_ONE,
	false),
  HOWTO(R_X86_64_GOTPC32, 0, 4, 32, true, 0, complain_overflow_signed,
	bfd_elf_generic_reloc, "R_X86_64_GOTPC32", false, 0, 0xffffffff,
	true),
  HOWTO(R_X86_64_GOT64, 0, 8, 64, false, 0, complain_overflow_signed,
	bfd_elf_generic_reloc, "R_X86_64_GOT64", false, 0, MINUS_ONE,
	false),
  HOWTO(R_X86_64_GOTPCREL64, 0, 8, 64, true, 0, complain_overflow_signed,
	bfd_elf_generic_reloc, "R_X86_64_GOTPCREL64", false, 0, MINUS_ONE,
	true),
  HOWTO(R_X86_64_GOTPC64, 0, 8, 64, true, 0, complain_overflow_signed,
	bfd_elf_generic_reloc, "R_X86_64_GOTPC64", false, 0, MINUS_ONE,
	true),
  HOWTO(R_X86_64_GOTPLT64, 0, 8, 64, false, 0, complain_overflow_signed,
	bfd_elf_generic_reloc, "R_X86_64_GOTPLT64", false, 0, MINUS_ONE,
	false),
  HOWTO(R_X86_64_PLTOFF64, 0, 8, 64, false, 0, complain_overflow_signed,
	bfd_elf_generic_reloc, "R_X86_64_PLTOFF64", false, 0, MINUS_ONE,
	false),
  HOWTO(R_X86_64_SIZE32, 0, 4, 32, false, 0, complain_overflow_unsigned,
	bfd_elf_generic_reloc, "R_X86_64_SIZE32", false, 0, 0xffffffff,
	false),
  HOWTO(R_X86_64_SIZE64, 0, 8, 64, false, 0, complain_overflow_dont,
	bfd_elf_generic_reloc, "R_X86_64_SIZE64", false, 0, MINUS_ONE,
	false),
  HOWTO(R_X86_64_GOTPC32_TLSDESC, 0, 4, 32, true, 0,
	complain_overflow_bitfield, bfd_elf_generic_reloc,
	"R_X86_64_GOTPC32_TLSDESC", false, 0, 0xffffffff, true),
  HOWTO(R_X86_64_TLSDESC_CALL, 0, 0, 0, false, 0,
	complain_overflow_dont, bfd_elf_generic_reloc,
	"R_X86_64_TLSDESC_CALL",
	false, 0, 0, false),
  HOWTO(R_X86_64_TLSDESC, 0, 8, 64, false, 0,
	complain_overflow_dont, bfd_elf_generic_reloc,
	"R_X86_64_TLSDESC", false, 0, MINUS_ONE, false),
  HOWTO(R_X86_64_IRELATIVE, 0, 8, 64, false, 0, complain_overflow_dont,
	bfd_elf_generic_reloc, "R_X86_64_IRELATIVE", false, 0, MINUS_ONE,
	false),
  HOWTO(R_X86_64_RELATIVE64, 0, 8, 64, false, 0, complain_overflow_dont,
	bfd_elf_generic_reloc, "R_X86_64_RELATIVE64", false, 0, MINUS_ONE,
	false),
  HOWTO(R_X86_64_PC32_BND, 0, 4, 32, true, 0, complain_overflow_signed,
	bfd_elf_generic_reloc, "R_X86_64_PC32_BND", false, 0, 0xffffffff,
	true),
  HOWTO(R_X86_64_PLT32_BND, 0, 4, 32, true, 0, complain_overflow_signed,
	bfd_elf_generic_reloc, "R_X86_64_PLT32_BND", false, 0, 0xffffffff,
	true),
  HOWTO(R_X86_64_GOTPCRELX, 0, 4, 32, true, 0, complain_overflow_signed,
	bfd_elf_generic_reloc, "R_X86_64_GOTPCRELX", false, 0, 0xffffffff,
	true),
  HOWTO(R_X86_64_REX_GOTPCRELX, 0, 4, 32, true, 0, complain_overflow_signed,
	bfd_elf_generic_reloc, "R_X86_64_REX_GOTPCRELX", false, 0, 0xffffffff,
	true),
  HOWTO(R_X86_64_CODE_4_GOTPCRELX, 0, 4, 32, true, 0, complain_overflow_signed,
	bfd_elf_generic_reloc, "R_X86_64_CODE_4_GOTPCRELX", false, 0, 0xffffffff,
	true),
  HOWTO(R_X86_64_CODE_4_GOTTPOFF, 0, 4, 32, true, 0, complain_overflow_signed,
	bfd_elf_generic_reloc, "R_X86_64_CODE_4_GOTTPOFF", false, 0, 0xffffffff,
	true),
  HOWTO(R_X86_64_CODE_4_GOTPC32_TLSDESC, 0, 4, 32, true, 0,
	complain_overflow_bitfield, bfd_elf_generic_reloc,
	"R_X86_64_CODE_4_GOTPC32_TLSDESC", false, 0, 0xffffffff, true),
  HOWTO(R_X86_64_CODE_5_GOTPCRELX, 0, 4, 32, true, 0,
	complain_overflow_signed, bfd_elf_generic_reloc,
	"R_X86_64_CODE_5_GOTPCRELX", false, 0, 0xffffffff, true),
  HOWTO(R_X86_64_CODE_5_GOTTPOFF, 0, 4, 32, true, 0,
	complain_overflow_signed, bfd_elf_generic_reloc,
	"R_X86_64_CODE_5_GOTTPOFF", false, 0, 0xffffffff, true),
  HOWTO(R_X86_64_CODE_5_GOTPC32_TLSDESC, 0, 4, 32, true, 0,
	complain_overflow_bitfield, bfd_elf_generic_reloc,
	"R_X86_64_CODE_5_GOTPC32_TLSDESC", false, 0, 0xffffffff, true),
  HOWTO(R_X86_64_CODE_6_GOTPCRELX, 0, 4, 32, true, 0,
	complain_overflow_signed, bfd_elf_generic_reloc,
	"R_X86_64_CODE_6_GOTPCRELX", false, 0, 0xffffffff, true),
  HOWTO(R_X86_64_CODE_6_GOTTPOFF, 0, 4, 32, true, 0,
	complain_overflow_signed, bfd_elf_generic_reloc,
	"R_X86_64_CODE_6_GOTTPOFF", false, 0, 0xffffffff, true),
  HOWTO(R_X86_64_CODE_6_GOTPC32_TLSDESC, 0, 4, 32, true, 0,
	complain_overflow_bitfield, bfd_elf_generic_reloc,
	"R_X86_64_CODE_6_GOTPC32_TLSDESC", false, 0, 0xffffffff, true),

  /* We have a gap in the reloc numbers here.
     R_X86_64_standard counts the number up to this point, and
     R_X86_64_vt_offset is the value to subtract from a reloc type of
     R_X86_64_GNU_VT* to form an index into this table.  */
#define R_X86_64_standard (R_X86_64_CODE_6_GOTPC32_TLSDESC + 1)
#define R_X86_64_vt_offset (R_X86_64_GNU_VTINHERIT - R_X86_64_standard)

/* GNU extension to record C++ vtable hierarchy.  */
  HOWTO (R_X86_64_GNU_VTINHERIT, 0, 8, 0, false, 0, complain_overflow_dont,
	 NULL, "R_X86_64_GNU_VTINHERIT", false, 0, 0, false),

/* GNU extension to record C++ vtable member usage.  */
  HOWTO (R_X86_64_GNU_VTENTRY, 0, 8, 0, false, 0, complain_overflow_dont,
	 _bfd_elf_rel_vtable_reloc_fn, "R_X86_64_GNU_VTENTRY", false, 0, 0,
	 false),

/* Use complain_overflow_bitfield on R_X86_64_32 for x32.  */
  HOWTO(R_X86_64_32, 0, 4, 32, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_X86_64_32", false, 0, 0xffffffff,
	false)
};

/* Map BFD relocs to the x86_64 elf relocs.  */
struct elf_reloc_map
{
  bfd_reloc_code_real_type bfd_reloc_val;
  unsigned char elf_reloc_val;
};

static const struct elf_reloc_map x86_64_reloc_map[] =
{
  { BFD_RELOC_NONE,		R_X86_64_NONE, },
  { BFD_RELOC_64,		R_X86_64_64,   },
  { BFD_RELOC_32_PCREL,		R_X86_64_PC32, },
  { BFD_RELOC_X86_64_GOT32,	R_X86_64_GOT32,},
  { BFD_RELOC_X86_64_PLT32,	R_X86_64_PLT32,},
  { BFD_RELOC_X86_64_COPY,	R_X86_64_COPY, },
  { BFD_RELOC_X86_64_GLOB_DAT,	R_X86_64_GLOB_DAT, },
  { BFD_RELOC_X86_64_JUMP_SLOT, R_X86_64_JUMP_SLOT, },
  { BFD_RELOC_X86_64_RELATIVE,	R_X86_64_RELATIVE, },
  { BFD_RELOC_X86_64_GOTPCREL,	R_X86_64_GOTPCREL, },
  { BFD_RELOC_32,		R_X86_64_32, },
  { BFD_RELOC_X86_64_32S,	R_X86_64_32S, },
  { BFD_RELOC_16,		R_X86_64_16, },
  { BFD_RELOC_16_PCREL,		R_X86_64_PC16, },
  { BFD_RELOC_8,		R_X86_64_8, },
  { BFD_RELOC_8_PCREL,		R_X86_64_PC8, },
  { BFD_RELOC_X86_64_DTPMOD64,	R_X86_64_DTPMOD64, },
  { BFD_RELOC_X86_64_DTPOFF64,	R_X86_64_DTPOFF64, },
  { BFD_RELOC_X86_64_TPOFF64,	R_X86_64_TPOFF64, },
  { BFD_RELOC_X86_64_TLSGD,	R_X86_64_TLSGD, },
  { BFD_RELOC_X86_64_TLSLD,	R_X86_64_TLSLD, },
  { BFD_RELOC_X86_64_DTPOFF32,	R_X86_64_DTPOFF32, },
  { BFD_RELOC_X86_64_GOTTPOFF,	R_X86_64_GOTTPOFF, },
  { BFD_RELOC_X86_64_TPOFF32,	R_X86_64_TPOFF32, },
  { BFD_RELOC_64_PCREL,		R_X86_64_PC64, },
  { BFD_RELOC_X86_64_GOTOFF64,	R_X86_64_GOTOFF64, },
  { BFD_RELOC_X86_64_GOTPC32,	R_X86_64_GOTPC32, },
  { BFD_RELOC_X86_64_GOT64,	R_X86_64_GOT64, },
  { BFD_RELOC_X86_64_GOTPCREL64,R_X86_64_GOTPCREL64, },
  { BFD_RELOC_X86_64_GOTPC64,	R_X86_64_GOTPC64, },
  { BFD_RELOC_X86_64_GOTPLT64,	R_X86_64_GOTPLT64, },
  { BFD_RELOC_X86_64_PLTOFF64,	R_X86_64_PLTOFF64, },
  { BFD_RELOC_SIZE32,		R_X86_64_SIZE32, },
  { BFD_RELOC_SIZE64,		R_X86_64_SIZE64, },
  { BFD_RELOC_X86_64_GOTPC32_TLSDESC, R_X86_64_GOTPC32_TLSDESC, },
  { BFD_RELOC_X86_64_TLSDESC_CALL, R_X86_64_TLSDESC_CALL, },
  { BFD_RELOC_X86_64_TLSDESC,	R_X86_64_TLSDESC, },
  { BFD_RELOC_X86_64_IRELATIVE,	R_X86_64_IRELATIVE, },
  { BFD_RELOC_X86_64_PC32_BND,	R_X86_64_PC32_BND, },
  { BFD_RELOC_X86_64_PLT32_BND,	R_X86_64_PLT32_BND, },
  { BFD_RELOC_X86_64_GOTPCRELX, R_X86_64_GOTPCRELX, },
  { BFD_RELOC_X86_64_REX_GOTPCRELX, R_X86_64_REX_GOTPCRELX, },
  { BFD_RELOC_X86_64_CODE_4_GOTPCRELX, R_X86_64_CODE_4_GOTPCRELX, },
  { BFD_RELOC_X86_64_CODE_4_GOTTPOFF, R_X86_64_CODE_4_GOTTPOFF, },
  { BFD_RELOC_X86_64_CODE_4_GOTPC32_TLSDESC, R_X86_64_CODE_4_GOTPC32_TLSDESC, },
  { BFD_RELOC_X86_64_CODE_5_GOTPCRELX, R_X86_64_CODE_5_GOTPCRELX, },
  { BFD_RELOC_X86_64_CODE_5_GOTTPOFF, R_X86_64_CODE_5_GOTTPOFF, },
  { BFD_RELOC_X86_64_CODE_5_GOTPC32_TLSDESC, R_X86_64_CODE_5_GOTPC32_TLSDESC, },
  { BFD_RELOC_X86_64_CODE_6_GOTPCRELX, R_X86_64_CODE_6_GOTPCRELX, },
  { BFD_RELOC_X86_64_CODE_6_GOTTPOFF, R_X86_64_CODE_6_GOTTPOFF, },
  { BFD_RELOC_X86_64_CODE_6_GOTPC32_TLSDESC, R_X86_64_CODE_6_GOTPC32_TLSDESC, },
  { BFD_RELOC_VTABLE_INHERIT,	R_X86_64_GNU_VTINHERIT, },
  { BFD_RELOC_VTABLE_ENTRY,	R_X86_64_GNU_VTENTRY, },
};

static reloc_howto_type *
elf_x86_64_rtype_to_howto(bfd *abfd, unsigned r_type)
{
    unsigned i;

    if (r_type == (unsigned int)R_X86_64_32) {
        i = ABI_64_P(abfd) ? r_type : ARRAY_SIZE(x86_64_elf_howto_table) - 1;
    } else if (r_type < (unsigned int)R_X86_64_GNU_VTINHERIT || r_type >= (unsigned int)R_X86_64_max) {
        if (r_type >= (unsigned int)R_X86_64_standard) {
            _bfd_error_handler(_("%pB: unsupported relocation type %#x"), abfd, r_type);
            bfd_set_error(bfd_error_bad_value);
            return NULL;
        }
        i = r_type;
    } else {
        i = r_type - (unsigned int)R_X86_64_vt_offset;
    }

    if (i >= ARRAY_SIZE(x86_64_elf_howto_table) || x86_64_elf_howto_table[i].type != r_type) {
        _bfd_error_handler(_("%pB: relocation type %#x mismatch or out-of-bounds"), abfd, r_type);
        bfd_set_error(bfd_error_bad_value);
        return NULL;
    }

    return &x86_64_elf_howto_table[i];
}

/* Given a BFD reloc type, return a HOWTO structure.  */
static reloc_howto_type *elf_x86_64_reloc_type_lookup(bfd *abfd, bfd_reloc_code_real_type code) {
    size_t i, map_size;
    if (!abfd)
        return NULL;
    map_size = sizeof(x86_64_reloc_map) / sizeof(x86_64_reloc_map[0]);
    for (i = 0; i < map_size; i++) {
        if (x86_64_reloc_map[i].bfd_reloc_val == code) {
            return elf_x86_64_rtype_to_howto(abfd, x86_64_reloc_map[i].elf_reloc_val);
        }
    }
    return NULL;
}

static reloc_howto_type *
elf_x86_64_reloc_name_lookup(bfd *abfd, const char *r_name)
{
    if (!abfd || !r_name) {
        return NULL;
    }

    if (!ABI_64_P(abfd) && strcasecmp(r_name, "R_X86_64_32") == 0) {
        size_t idx = ARRAY_SIZE(x86_64_elf_howto_table) - 1;
        reloc_howto_type *reloc = &x86_64_elf_howto_table[idx];
        if (reloc->type == (unsigned int)R_X86_64_32) {
            return reloc;
        }
        return NULL;
    }

    for (unsigned int i = 0; i < ARRAY_SIZE(x86_64_elf_howto_table); ++i) {
        const char *name = x86_64_elf_howto_table[i].name;
        if (name && strcasecmp(name, r_name) == 0) {
            return &x86_64_elf_howto_table[i];
        }
    }
    return NULL;
}

/* Given an x86_64 ELF reloc type, fill in an arelent structure.  */

static bool elf_x86_64_info_to_howto(bfd *abfd, arelent *cache_ptr, Elf_Internal_Rela *dst) {
    unsigned r_type = ELF32_R_TYPE(dst->r_info);
    cache_ptr->howto = elf_x86_64_rtype_to_howto(abfd, r_type);
    if (!cache_ptr->howto)
        return false;
    if (cache_ptr->howto->type != r_type && cache_ptr->howto->type != R_X86_64_NONE)
        return false;
    return true;
}

/* Support for core dump NOTE sections.  */
static bool elf_x86_64_grok_prstatus(bfd *abfd, Elf_Internal_Note *note)
{
    int offset = 0;
    size_t size = 0;
    const unsigned char *descdata = note->descdata;

    if (note->descsz == 296) {
        elf_tdata(abfd)->core->signal = bfd_get_16(abfd, descdata + 12);
        elf_tdata(abfd)->core->lwpid = bfd_get_32(abfd, descdata + 24);
        offset = 72;
        size = 216;
    } else if (note->descsz == 336) {
        elf_tdata(abfd)->core->signal = bfd_get_16(abfd, descdata + 12);
        elf_tdata(abfd)->core->lwpid = bfd_get_32(abfd, descdata + 32);
        offset = 112;
        size = 216;
    } else {
        return false;
    }

    return _bfd_elfcore_make_pseudosection(abfd, ".reg", size, note->descpos + offset);
}

static bool
elf_x86_64_grok_psinfo(bfd *abfd, Elf_Internal_Note *note)
{
    int pid_offset = 0, program_offset = 0, command_offset = 0;

    if (!abfd || !note || !note->descdata)
        return false;

    switch (note->descsz) {
        case 124:
            pid_offset = 12;
            program_offset = 28;
            command_offset = 44;
            break;
        case 128:
            pid_offset = 12;
            program_offset = 32;
            command_offset = 48;
            break;
        case 136:
            pid_offset = 24;
            program_offset = 40;
            command_offset = 56;
            break;
        default:
            return false;
    }

    elf_tdata(abfd)->core->pid = bfd_get_32(abfd, note->descdata + pid_offset);

    char *program = _bfd_elfcore_strndup(abfd, note->descdata + program_offset, 16);
    if (!program)
        return false;
    elf_tdata(abfd)->core->program = program;

    char *command = _bfd_elfcore_strndup(abfd, note->descdata + command_offset, 80);
    if (!command)
        return false;
    elf_tdata(abfd)->core->command = command;

    int n = strlen(command);
    if (n > 0 && command[n - 1] == ' ')
        command[n - 1] = '\0';

    return true;
}

#ifdef CORE_HEADER
# if GCC_VERSION >= 8000
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wstringop-truncation"
# endif
static char *
elf_x86_64_write_core_note (bfd *abfd, char *buf, int *bufsiz,
			    int note_type, ...)
{
  const struct elf_backend_data *bed = get_elf_backend_data (abfd);
  va_list ap;
  const char *fname, *psargs;
  long pid;
  int cursig;
  const void *gregs;

  switch (note_type)
    {
    default:
      return NULL;

    case NT_PRPSINFO:
      va_start (ap, note_type);
      fname = va_arg (ap, const char *);
      psargs = va_arg (ap, const char *);
      va_end (ap);

      if (bed->s->elfclass == ELFCLASS32)
	{
	  prpsinfo32_t data;
	  memset (&data, 0, sizeof (data));
	  strncpy (data.pr_fname, fname, sizeof (data.pr_fname));
	  strncpy (data.pr_psargs, psargs, sizeof (data.pr_psargs));
	  return elfcore_write_note (abfd, buf, bufsiz, "CORE", note_type,
				     &data, sizeof (data));
	}
      else
	{
	  prpsinfo64_t data;
	  memset (&data, 0, sizeof (data));
	  strncpy (data.pr_fname, fname, sizeof (data.pr_fname));
	  strncpy (data.pr_psargs, psargs, sizeof (data.pr_psargs));
	  return elfcore_write_note (abfd, buf, bufsiz, "CORE", note_type,
				     &data, sizeof (data));
	}
      /* NOTREACHED */

    case NT_PRSTATUS:
      va_start (ap, note_type);
      pid = va_arg (ap, long);
      cursig = va_arg (ap, int);
      gregs = va_arg (ap, const void *);
      va_end (ap);

      if (bed->s->elfclass == ELFCLASS32)
	{
	  if (bed->elf_machine_code == EM_X86_64)
	    {
	      prstatusx32_t prstat;
	      memset (&prstat, 0, sizeof (prstat));
	      prstat.pr_pid = pid;
	      prstat.pr_cursig = cursig;
	      memcpy (&prstat.pr_reg, gregs, sizeof (prstat.pr_reg));
	      return elfcore_write_note (abfd, buf, bufsiz, "CORE", note_type,
					 &prstat, sizeof (prstat));
	    }
	  else
	    {
	      prstatus32_t prstat;
	      memset (&prstat, 0, sizeof (prstat));
	      prstat.pr_pid = pid;
	      prstat.pr_cursig = cursig;
	      memcpy (&prstat.pr_reg, gregs, sizeof (prstat.pr_reg));
	      return elfcore_write_note (abfd, buf, bufsiz, "CORE", note_type,
					 &prstat, sizeof (prstat));
	    }
	}
      else
	{
	  prstatus64_t prstat;
	  memset (&prstat, 0, sizeof (prstat));
	  prstat.pr_pid = pid;
	  prstat.pr_cursig = cursig;
	  memcpy (&prstat.pr_reg, gregs, sizeof (prstat.pr_reg));
	  return elfcore_write_note (abfd, buf, bufsiz, "CORE", note_type,
				     &prstat, sizeof (prstat));
	}
    }
  /* NOTREACHED */
}
# if GCC_VERSION >= 8000
#  pragma GCC diagnostic pop
# endif
#endif

/* Functions for the x86-64 ELF linker.	 */

/* The size in bytes of an entry in the global offset table.  */

#define GOT_ENTRY_SIZE 8

/* The size in bytes of an entry in the lazy procedure linkage table.  */

#define LAZY_PLT_ENTRY_SIZE 16

/* The size in bytes of an entry in the non-lazy procedure linkage
   table.  */

#define NON_LAZY_PLT_ENTRY_SIZE 8

/* The first entry in a lazy procedure linkage table looks like this.
   See the SVR4 ABI i386 supplement and the x86-64 ABI to see how this
   works.  */

static const bfd_byte elf_x86_64_lazy_plt0_entry[LAZY_PLT_ENTRY_SIZE] =
{
  0xff, 0x35, 8, 0, 0, 0,	/* pushq GOT+8(%rip)  */
  0xff, 0x25, 16, 0, 0, 0,	/* jmpq *GOT+16(%rip) */
  0x0f, 0x1f, 0x40, 0x00	/* nopl 0(%rax)       */
};

/* Subsequent entries in a lazy procedure linkage table look like this.  */

static const bfd_byte elf_x86_64_lazy_plt_entry[LAZY_PLT_ENTRY_SIZE] =
{
  0xff, 0x25,	/* jmpq *name@GOTPC(%rip) */
  0, 0, 0, 0,	/* replaced with offset to this symbol in .got.	 */
  0x68,		/* pushq immediate */
  0, 0, 0, 0,	/* replaced with index into relocation table.  */
  0xe9,		/* jmp relative */
  0, 0, 0, 0	/* replaced with offset to start of .plt0.  */
};

/* The first entry in a lazy procedure linkage table with BND prefix
   like this.  */

static const bfd_byte elf_x86_64_lazy_bnd_plt0_entry[LAZY_PLT_ENTRY_SIZE] =
{
  0xff, 0x35, 8, 0, 0, 0,	  /* pushq GOT+8(%rip)	      */
  0xf2, 0xff, 0x25, 16, 0, 0, 0,  /* bnd jmpq *GOT+16(%rip)   */
  0x0f, 0x1f, 0			  /* nopl (%rax)	      */
};

/* Subsequent entries for branches with BND prefx in a lazy procedure
   linkage table look like this.  */

static const bfd_byte elf_x86_64_lazy_bnd_plt_entry[LAZY_PLT_ENTRY_SIZE] =
{
  0x68, 0, 0, 0, 0,		/* pushq immediate	      */
  0xf2, 0xe9, 0, 0, 0, 0,	/* bnd jmpq relative	      */
  0x0f, 0x1f, 0x44, 0, 0	/* nopl 0(%rax,%rax,1)	      */
};

/* The first entry in the IBT-enabled lazy procedure linkage table is the
   the same as the lazy PLT with BND prefix so that bound registers are
   preserved when control is passed to dynamic linker.  Subsequent
   entries for a IBT-enabled lazy procedure linkage table look like
   this.  */

static const bfd_byte elf_x86_64_lazy_bnd_ibt_plt_entry[LAZY_PLT_ENTRY_SIZE] =
{
  0xf3, 0x0f, 0x1e, 0xfa,	/* endbr64		      */
  0x68, 0, 0, 0, 0,		/* pushq immediate	      */
  0xf2, 0xe9, 0, 0, 0, 0,	/* bnd jmpq relative	      */
  0x90				/* nop			      */
};

/* The first entry in the IBT-enabled lazy procedure linkage table
   is the same as the normal lazy PLT.  Subsequent entries for an
   IBT-enabled lazy procedure linkage table look like this.  */

static const bfd_byte elf_x86_64_lazy_ibt_plt_entry[LAZY_PLT_ENTRY_SIZE] =
{
  0xf3, 0x0f, 0x1e, 0xfa,	/* endbr64		      */
  0x68, 0, 0, 0, 0,		/* pushq immediate	      */
  0xe9, 0, 0, 0, 0,		/* jmpq relative	      */
  0x66, 0x90			/* xchg %ax,%ax		      */
};

/* Entries in the non-lazey procedure linkage table look like this.  */

static const bfd_byte elf_x86_64_non_lazy_plt_entry[NON_LAZY_PLT_ENTRY_SIZE] =
{
  0xff, 0x25,	     /* jmpq *name@GOTPC(%rip)			      */
  0, 0, 0, 0,	     /* replaced with offset to this symbol in .got.  */
  0x66, 0x90	     /* xchg %ax,%ax				      */
};

/* Entries for branches with BND prefix in the non-lazey procedure
   linkage table look like this.  */

static const bfd_byte elf_x86_64_non_lazy_bnd_plt_entry[NON_LAZY_PLT_ENTRY_SIZE] =
{
  0xf2, 0xff, 0x25,  /* bnd jmpq *name@GOTPC(%rip)		      */
  0, 0, 0, 0,	     /* replaced with offset to this symbol in .got.  */
  0x90		     /* nop					      */
};

/* Entries for IBT-enabled branches with BND prefix in the non-lazey
   procedure linkage table look like this.  They have the same size as
   the lazy PLT entry.  */

static const bfd_byte elf_x86_64_non_lazy_bnd_ibt_plt_entry[LAZY_PLT_ENTRY_SIZE] =
{
  0xf3, 0x0f, 0x1e, 0xfa,	/* endbr64		       */
  0xf2, 0xff, 0x25,		/* bnd jmpq *name@GOTPC(%rip)  */
  0, 0, 0, 0,  /* replaced with offset to this symbol in .got. */
  0x0f, 0x1f, 0x44, 0x00, 0x00	/* nopl 0x0(%rax,%rax,1)       */
};

/* Entries for branches with IBT-enabled in the non-lazey procedure
   linkage table look like this.  They have the same size as the lazy
   PLT entry.  */

static const bfd_byte elf_x86_64_non_lazy_ibt_plt_entry[LAZY_PLT_ENTRY_SIZE] =
{
  0xf3, 0x0f, 0x1e, 0xfa,	     /* endbr64		       */
  0xff, 0x25,			     /* jmpq *name@GOTPC(%rip) */
  0, 0, 0, 0,  /* replaced with offset to this symbol in .got. */
  0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00 /* nopw 0x0(%rax,%rax,1)  */
};

/* The TLSDESC entry in a lazy procedure linkage table.  */
static const bfd_byte elf_x86_64_tlsdesc_plt_entry[LAZY_PLT_ENTRY_SIZE] =
{
  0xf3, 0x0f, 0x1e, 0xfa,	     /* endbr64		       */
  0xff, 0x35, 8, 0, 0, 0,	     /* pushq GOT+8(%rip)	*/
  0xff, 0x25, 16, 0, 0, 0	     /* jmpq *GOT+TDG(%rip)	*/
};

/* .eh_frame covering the lazy .plt section.  */

static const bfd_byte elf_x86_64_eh_frame_lazy_plt[] =
{
  PLT_CIE_LENGTH, 0, 0, 0,	/* CIE length */
  0, 0, 0, 0,			/* CIE ID */
  1,				/* CIE version */
  'z', 'R', 0,			/* Augmentation string */
  1,				/* Code alignment factor */
  0x78,				/* Data alignment factor */
  16,				/* Return address column */
  1,				/* Augmentation size */
  DW_EH_PE_pcrel | DW_EH_PE_sdata4, /* FDE encoding */
  DW_CFA_def_cfa, 7, 8,		/* DW_CFA_def_cfa: r7 (rsp) ofs 8 */
  DW_CFA_offset + 16, 1,	/* DW_CFA_offset: r16 (rip) at cfa-8 */
  DW_CFA_nop, DW_CFA_nop,

  PLT_FDE_LENGTH, 0, 0, 0,	/* FDE length */
  PLT_CIE_LENGTH + 8, 0, 0, 0,	/* CIE pointer */
  0, 0, 0, 0,			/* R_X86_64_PC32 .plt goes here */
  0, 0, 0, 0,			/* .plt size goes here */
  0,				/* Augmentation size */
  DW_CFA_def_cfa_offset, 16,	/* DW_CFA_def_cfa_offset: 16 */
  DW_CFA_advance_loc + 6,	/* DW_CFA_advance_loc: 6 to __PLT__+6 */
  DW_CFA_def_cfa_offset, 24,	/* DW_CFA_def_cfa_offset: 24 */
  DW_CFA_advance_loc + 10,	/* DW_CFA_advance_loc: 10 to __PLT__+16 */
  DW_CFA_def_cfa_expression,	/* DW_CFA_def_cfa_expression */
  11,				/* Block length */
  DW_OP_breg7, 8,		/* DW_OP_breg7 (rsp): 8 */
  DW_OP_breg16, 0,		/* DW_OP_breg16 (rip): 0 */
  DW_OP_lit15, DW_OP_and, DW_OP_lit11, DW_OP_ge,
  DW_OP_lit3, DW_OP_shl, DW_OP_plus,
  DW_CFA_nop, DW_CFA_nop, DW_CFA_nop, DW_CFA_nop
};

/* .eh_frame covering the lazy BND .plt section.  */

static const bfd_byte elf_x86_64_eh_frame_lazy_bnd_plt[] =
{
  PLT_CIE_LENGTH, 0, 0, 0,	/* CIE length */
  0, 0, 0, 0,			/* CIE ID */
  1,				/* CIE version */
  'z', 'R', 0,			/* Augmentation string */
  1,				/* Code alignment factor */
  0x78,				/* Data alignment factor */
  16,				/* Return address column */
  1,				/* Augmentation size */
  DW_EH_PE_pcrel | DW_EH_PE_sdata4, /* FDE encoding */
  DW_CFA_def_cfa, 7, 8,		/* DW_CFA_def_cfa: r7 (rsp) ofs 8 */
  DW_CFA_offset + 16, 1,	/* DW_CFA_offset: r16 (rip) at cfa-8 */
  DW_CFA_nop, DW_CFA_nop,

  PLT_FDE_LENGTH, 0, 0, 0,	/* FDE length */
  PLT_CIE_LENGTH + 8, 0, 0, 0,	/* CIE pointer */
  0, 0, 0, 0,			/* R_X86_64_PC32 .plt goes here */
  0, 0, 0, 0,			/* .plt size goes here */
  0,				/* Augmentation size */
  DW_CFA_def_cfa_offset, 16,	/* DW_CFA_def_cfa_offset: 16 */
  DW_CFA_advance_loc + 6,	/* DW_CFA_advance_loc: 6 to __PLT__+6 */
  DW_CFA_def_cfa_offset, 24,	/* DW_CFA_def_cfa_offset: 24 */
  DW_CFA_advance_loc + 10,	/* DW_CFA_advance_loc: 10 to __PLT__+16 */
  DW_CFA_def_cfa_expression,	/* DW_CFA_def_cfa_expression */
  11,				/* Block length */
  DW_OP_breg7, 8,		/* DW_OP_breg7 (rsp): 8 */
  DW_OP_breg16, 0,		/* DW_OP_breg16 (rip): 0 */
  DW_OP_lit15, DW_OP_and, DW_OP_lit5, DW_OP_ge,
  DW_OP_lit3, DW_OP_shl, DW_OP_plus,
  DW_CFA_nop, DW_CFA_nop, DW_CFA_nop, DW_CFA_nop
};

/* .eh_frame covering the lazy .plt section with IBT-enabled and BND
   prefix.  */

static const bfd_byte elf_x86_64_eh_frame_lazy_bnd_ibt_plt[] =
{
  PLT_CIE_LENGTH, 0, 0, 0,	/* CIE length */
  0, 0, 0, 0,			/* CIE ID */
  1,				/* CIE version */
  'z', 'R', 0,			/* Augmentation string */
  1,				/* Code alignment factor */
  0x78,				/* Data alignment factor */
  16,				/* Return address column */
  1,				/* Augmentation size */
  DW_EH_PE_pcrel | DW_EH_PE_sdata4, /* FDE encoding */
  DW_CFA_def_cfa, 7, 8,		/* DW_CFA_def_cfa: r7 (rsp) ofs 8 */
  DW_CFA_offset + 16, 1,	/* DW_CFA_offset: r16 (rip) at cfa-8 */
  DW_CFA_nop, DW_CFA_nop,

  PLT_FDE_LENGTH, 0, 0, 0,	/* FDE length */
  PLT_CIE_LENGTH + 8, 0, 0, 0,	/* CIE pointer */
  0, 0, 0, 0,			/* R_X86_64_PC32 .plt goes here */
  0, 0, 0, 0,			/* .plt size goes here */
  0,				/* Augmentation size */
  DW_CFA_def_cfa_offset, 16,	/* DW_CFA_def_cfa_offset: 16 */
  DW_CFA_advance_loc + 6,	/* DW_CFA_advance_loc: 6 to __PLT__+6 */
  DW_CFA_def_cfa_offset, 24,	/* DW_CFA_def_cfa_offset: 24 */
  DW_CFA_advance_loc + 10,	/* DW_CFA_advance_loc: 10 to __PLT__+16 */
  DW_CFA_def_cfa_expression,	/* DW_CFA_def_cfa_expression */
  11,				/* Block length */
  DW_OP_breg7, 8,		/* DW_OP_breg7 (rsp): 8 */
  DW_OP_breg16, 0,		/* DW_OP_breg16 (rip): 0 */
  DW_OP_lit15, DW_OP_and, DW_OP_lit10, DW_OP_ge,
  DW_OP_lit3, DW_OP_shl, DW_OP_plus,
  DW_CFA_nop, DW_CFA_nop, DW_CFA_nop, DW_CFA_nop
};

/* .eh_frame covering the lazy .plt section with IBT-enabled.  */

static const bfd_byte elf_x86_64_eh_frame_lazy_ibt_plt[] =
{
  PLT_CIE_LENGTH, 0, 0, 0,	/* CIE length */
  0, 0, 0, 0,			/* CIE ID */
  1,				/* CIE version */
  'z', 'R', 0,			/* Augmentation string */
  1,				/* Code alignment factor */
  0x78,				/* Data alignment factor */
  16,				/* Return address column */
  1,				/* Augmentation size */
  DW_EH_PE_pcrel | DW_EH_PE_sdata4, /* FDE encoding */
  DW_CFA_def_cfa, 7, 8,		/* DW_CFA_def_cfa: r7 (rsp) ofs 8 */
  DW_CFA_offset + 16, 1,	/* DW_CFA_offset: r16 (rip) at cfa-8 */
  DW_CFA_nop, DW_CFA_nop,

  PLT_FDE_LENGTH, 0, 0, 0,	/* FDE length */
  PLT_CIE_LENGTH + 8, 0, 0, 0,	/* CIE pointer */
  0, 0, 0, 0,			/* R_X86_64_PC32 .plt goes here */
  0, 0, 0, 0,			/* .plt size goes here */
  0,				/* Augmentation size */
  DW_CFA_def_cfa_offset, 16,	/* DW_CFA_def_cfa_offset: 16 */
  DW_CFA_advance_loc + 6,	/* DW_CFA_advance_loc: 6 to __PLT__+6 */
  DW_CFA_def_cfa_offset, 24,	/* DW_CFA_def_cfa_offset: 24 */
  DW_CFA_advance_loc + 10,	/* DW_CFA_advance_loc: 10 to __PLT__+16 */
  DW_CFA_def_cfa_expression,	/* DW_CFA_def_cfa_expression */
  11,				/* Block length */
  DW_OP_breg7, 8,		/* DW_OP_breg7 (rsp): 8 */
  DW_OP_breg16, 0,		/* DW_OP_breg16 (rip): 0 */
  DW_OP_lit15, DW_OP_and, DW_OP_lit9, DW_OP_ge,
  DW_OP_lit3, DW_OP_shl, DW_OP_plus,
  DW_CFA_nop, DW_CFA_nop, DW_CFA_nop, DW_CFA_nop
};

/* .eh_frame covering the non-lazy .plt section.  */

static const bfd_byte elf_x86_64_eh_frame_non_lazy_plt[] =
{
#define PLT_GOT_FDE_LENGTH		20
  PLT_CIE_LENGTH, 0, 0, 0,	/* CIE length */
  0, 0, 0, 0,			/* CIE ID */
  1,				/* CIE version */
  'z', 'R', 0,			/* Augmentation string */
  1,				/* Code alignment factor */
  0x78,				/* Data alignment factor */
  16,				/* Return address column */
  1,				/* Augmentation size */
  DW_EH_PE_pcrel | DW_EH_PE_sdata4, /* FDE encoding */
  DW_CFA_def_cfa, 7, 8,		/* DW_CFA_def_cfa: r7 (rsp) ofs 8 */
  DW_CFA_offset + 16, 1,	/* DW_CFA_offset: r16 (rip) at cfa-8 */
  DW_CFA_nop, DW_CFA_nop,

  PLT_GOT_FDE_LENGTH, 0, 0, 0,	/* FDE length */
  PLT_CIE_LENGTH + 8, 0, 0, 0,	/* CIE pointer */
  0, 0, 0, 0,			/* the start of non-lazy .plt goes here */
  0, 0, 0, 0,			/* non-lazy .plt size goes here */
  0,				/* Augmentation size */
  DW_CFA_nop, DW_CFA_nop, DW_CFA_nop, DW_CFA_nop,
  DW_CFA_nop, DW_CFA_nop, DW_CFA_nop
};

/* .sframe FRE covering the .plt section entry.  */
static const sframe_frame_row_entry elf_x86_64_sframe_plt0_fre1 =
{
  0, /* SFrame FRE start address.  */
  {16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, /* 12 bytes.  */
  SFRAME_V1_FRE_INFO (SFRAME_BASE_REG_SP, 1, SFRAME_FRE_OFFSET_1B) /* FRE info.  */
};

/* .sframe FRE covering the .plt section entry.  */
static const sframe_frame_row_entry elf_x86_64_sframe_plt0_fre2 =
{
  6, /* SFrame FRE start address.  */
  {24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, /* 12 bytes.  */
  SFRAME_V1_FRE_INFO (SFRAME_BASE_REG_SP, 1, SFRAME_FRE_OFFSET_1B) /* FRE info.  */
};

/* .sframe FRE covering the .plt section entry.  */
static const sframe_frame_row_entry elf_x86_64_sframe_pltn_fre1 =
{
  0, /* SFrame FRE start address.  */
  {8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, /* 12 bytes.  */
  SFRAME_V1_FRE_INFO (SFRAME_BASE_REG_SP, 1, SFRAME_FRE_OFFSET_1B) /* FRE info.  */
};

/* .sframe FRE covering the .plt section entry.  */
static const sframe_frame_row_entry elf_x86_64_sframe_pltn_fre2 =
{
  11, /* SFrame FRE start address.  */
  {16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, /* 12 bytes.  */
  SFRAME_V1_FRE_INFO (SFRAME_BASE_REG_SP, 1, SFRAME_FRE_OFFSET_1B) /* FRE info.  */
};

/* .sframe FRE covering the .plt section entry for IBT.  */
static const sframe_frame_row_entry elf_x86_64_sframe_ibt_pltn_fre2 =
{
  9, /* SFrame FRE start address.  */
  {16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, /* 12 bytes.  */
  SFRAME_V1_FRE_INFO (SFRAME_BASE_REG_SP, 1, SFRAME_FRE_OFFSET_1B) /* FRE info.  */
};

/* .sframe FRE covering the second .plt section entry.  */
static const sframe_frame_row_entry elf_x86_64_sframe_sec_pltn_fre1 =
{
  0, /* SFrame FRE start address.  */
  {8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, /* 12 bytes.  */
  SFRAME_V1_FRE_INFO (SFRAME_BASE_REG_SP, 1, SFRAME_FRE_OFFSET_1B) /* FRE info.  */
};

/* .sframe FRE covering the .plt.got section entry.  */
static const sframe_frame_row_entry elf_x86_64_sframe_pltgot_fre1 =
{
  0, /* SFrame FRE start address.  */
  {16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, /* 12 bytes.  */
  SFRAME_V1_FRE_INFO (SFRAME_BASE_REG_SP, 1, SFRAME_FRE_OFFSET_1B) /* FRE info.  */
};

/* SFrame helper object for non-lazy PLT.  */
static const struct elf_x86_sframe_plt elf_x86_64_sframe_non_lazy_plt =
{
  LAZY_PLT_ENTRY_SIZE,
  2, /* Number of FREs for PLT0.  */
  /* Array of SFrame FREs for plt0.  */
  { &elf_x86_64_sframe_plt0_fre1, &elf_x86_64_sframe_plt0_fre2 },
  LAZY_PLT_ENTRY_SIZE,
  1, /* Number of FREs for PLTn.  */
  /* Array of SFrame FREs for plt.  */
  { &elf_x86_64_sframe_sec_pltn_fre1 },
  0,
  0, /* There is no second PLT necessary.  */
  { },
  NON_LAZY_PLT_ENTRY_SIZE,
  1, /* Number of FREs for PLT GOT.  */
  /* Array of SFrame FREs for PLT GOT.  */
  { &elf_x86_64_sframe_pltgot_fre1 },
};

/* SFrame helper object for non-lazy IBT enabled PLT.  */
static const struct elf_x86_sframe_plt elf_x86_64_sframe_non_lazy_ibt_plt =
{
  LAZY_PLT_ENTRY_SIZE,
  2, /* Number of FREs for PLT0.  */
  /* Array of SFrame FREs for plt0.  */
  { &elf_x86_64_sframe_plt0_fre1, &elf_x86_64_sframe_plt0_fre2 },
  LAZY_PLT_ENTRY_SIZE,
  1, /* Number of FREs for PLTn.  */
  /* Array of SFrame FREs for plt.  */
  { &elf_x86_64_sframe_sec_pltn_fre1 },
  0,
  0, /* There is no second PLT necessary.  */
  { },
  LAZY_PLT_ENTRY_SIZE,
  1, /* Number of FREs for PLT GOT.  */
  /* Array of SFrame FREs for PLT GOT.  */
  { &elf_x86_64_sframe_pltgot_fre1 },
};

/* SFrame helper object for lazy PLT. */
static const struct elf_x86_sframe_plt elf_x86_64_sframe_plt =
{
  LAZY_PLT_ENTRY_SIZE,
  2, /* Number of FREs for PLT0.  */
  /* Array of SFrame FREs for plt0.  */
  { &elf_x86_64_sframe_plt0_fre1, &elf_x86_64_sframe_plt0_fre2 },
  LAZY_PLT_ENTRY_SIZE,
  2, /* Number of FREs for PLTn.  */
  /* Array of SFrame FREs for plt.  */
  { &elf_x86_64_sframe_pltn_fre1, &elf_x86_64_sframe_pltn_fre2 },
  NON_LAZY_PLT_ENTRY_SIZE,
  1, /* Number of FREs for second PLT.  */
  /* Array of SFrame FREs for second PLT.  */
  { &elf_x86_64_sframe_sec_pltn_fre1 },
  NON_LAZY_PLT_ENTRY_SIZE,
  1, /* Number of FREs for PLT GOT.  */
  /* Array of SFrame FREs for PLT GOT.  */
  { &elf_x86_64_sframe_pltgot_fre1 },
};

/* SFrame helper object for lazy PLT with IBT. */
static const struct elf_x86_sframe_plt elf_x86_64_sframe_ibt_plt =
{
  LAZY_PLT_ENTRY_SIZE,
  2, /* Number of FREs for PLT0.  */
  /* Array of SFrame FREs for plt0.  */
  { &elf_x86_64_sframe_plt0_fre1, &elf_x86_64_sframe_plt0_fre2 },
  LAZY_PLT_ENTRY_SIZE,
  2, /* Number of FREs for PLTn.  */
  /* Array of SFrame FREs for plt.  */
  { &elf_x86_64_sframe_pltn_fre1, &elf_x86_64_sframe_ibt_pltn_fre2 },
  LAZY_PLT_ENTRY_SIZE,
  1, /* Number of FREs for second PLT.  */
  /* Array of SFrame FREs for second plt.  */
  { &elf_x86_64_sframe_sec_pltn_fre1 },
  LAZY_PLT_ENTRY_SIZE,
  1, /* Number of FREs for PLT GOT.  */
  /* Array of SFrame FREs for PLT GOT.  */
  { &elf_x86_64_sframe_pltgot_fre1 },
};

/* These are the standard parameters.  */
static const struct elf_x86_lazy_plt_layout elf_x86_64_lazy_plt =
  {
    elf_x86_64_lazy_plt0_entry,		/* plt0_entry */
    LAZY_PLT_ENTRY_SIZE,		/* plt0_entry_size */
    elf_x86_64_lazy_plt_entry,		/* plt_entry */
    LAZY_PLT_ENTRY_SIZE,		/* plt_entry_size */
    elf_x86_64_tlsdesc_plt_entry,	/* plt_tlsdesc_entry */
    LAZY_PLT_ENTRY_SIZE,		/* plt_tlsdesc_entry_size */
    6,					/* plt_tlsdesc_got1_offset */
    12,					/* plt_tlsdesc_got2_offset */
    10,					/* plt_tlsdesc_got1_insn_end */
    16,					/* plt_tlsdesc_got2_insn_end */
    2,					/* plt0_got1_offset */
    8,					/* plt0_got2_offset */
    12,					/* plt0_got2_insn_end */
    2,					/* plt_got_offset */
    7,					/* plt_reloc_offset */
    12,					/* plt_plt_offset */
    6,					/* plt_got_insn_size */
    LAZY_PLT_ENTRY_SIZE,		/* plt_plt_insn_end */
    6,					/* plt_lazy_offset */
    elf_x86_64_lazy_plt0_entry,		/* pic_plt0_entry */
    elf_x86_64_lazy_plt_entry,		/* pic_plt_entry */
    elf_x86_64_eh_frame_lazy_plt,	/* eh_frame_plt */
    sizeof (elf_x86_64_eh_frame_lazy_plt) /* eh_frame_plt_size */
  };

static const struct elf_x86_non_lazy_plt_layout elf_x86_64_non_lazy_plt =
  {
    elf_x86_64_non_lazy_plt_entry,	/* plt_entry */
    elf_x86_64_non_lazy_plt_entry,	/* pic_plt_entry */
    NON_LAZY_PLT_ENTRY_SIZE,		/* plt_entry_size */
    2,					/* plt_got_offset */
    6,					/* plt_got_insn_size */
    elf_x86_64_eh_frame_non_lazy_plt,	/* eh_frame_plt */
    sizeof (elf_x86_64_eh_frame_non_lazy_plt) /* eh_frame_plt_size */
  };

static const struct elf_x86_lazy_plt_layout elf_x86_64_lazy_bnd_plt =
  {
    elf_x86_64_lazy_bnd_plt0_entry,	/* plt0_entry */
    LAZY_PLT_ENTRY_SIZE,		/* plt0_entry_size */
    elf_x86_64_lazy_bnd_plt_entry,	/* plt_entry */
    LAZY_PLT_ENTRY_SIZE,		/* plt_entry_size */
    elf_x86_64_tlsdesc_plt_entry,	/* plt_tlsdesc_entry */
    LAZY_PLT_ENTRY_SIZE,		/* plt_tlsdesc_entry_size */
    6,					/* plt_tlsdesc_got1_offset */
    12,					/* plt_tlsdesc_got2_offset */
    10,					/* plt_tlsdesc_got1_insn_end */
    16,					/* plt_tlsdesc_got2_insn_end */
    2,					/* plt0_got1_offset */
    1+8,				/* plt0_got2_offset */
    1+12,				/* plt0_got2_insn_end */
    1+2,				/* plt_got_offset */
    1,					/* plt_reloc_offset */
    7,					/* plt_plt_offset */
    1+6,				/* plt_got_insn_size */
    11,					/* plt_plt_insn_end */
    0,					/* plt_lazy_offset */
    elf_x86_64_lazy_bnd_plt0_entry,	/* pic_plt0_entry */
    elf_x86_64_lazy_bnd_plt_entry,	/* pic_plt_entry */
    elf_x86_64_eh_frame_lazy_bnd_plt,	/* eh_frame_plt */
    sizeof (elf_x86_64_eh_frame_lazy_bnd_plt) /* eh_frame_plt_size */
  };

static const struct elf_x86_non_lazy_plt_layout elf_x86_64_non_lazy_bnd_plt =
  {
    elf_x86_64_non_lazy_bnd_plt_entry,	/* plt_entry */
    elf_x86_64_non_lazy_bnd_plt_entry,	/* pic_plt_entry */
    NON_LAZY_PLT_ENTRY_SIZE,		/* plt_entry_size */
    1+2,				/* plt_got_offset */
    1+6,				/* plt_got_insn_size */
    elf_x86_64_eh_frame_non_lazy_plt,	/* eh_frame_plt */
    sizeof (elf_x86_64_eh_frame_non_lazy_plt) /* eh_frame_plt_size */
  };

static const struct elf_x86_lazy_plt_layout elf_x86_64_lazy_bnd_ibt_plt =
  {
    elf_x86_64_lazy_bnd_plt0_entry,	/* plt0_entry */
    LAZY_PLT_ENTRY_SIZE,		/* plt0_entry_size */
    elf_x86_64_lazy_bnd_ibt_plt_entry,	/* plt_entry */
    LAZY_PLT_ENTRY_SIZE,		/* plt_entry_size */
    elf_x86_64_tlsdesc_plt_entry,	/* plt_tlsdesc_entry */
    LAZY_PLT_ENTRY_SIZE,		/* plt_tlsdesc_entry_size */
    6,					/* plt_tlsdesc_got1_offset */
    12,					/* plt_tlsdesc_got2_offset */
    10,					/* plt_tlsdesc_got1_insn_end */
    16,					/* plt_tlsdesc_got2_insn_end */
    2,					/* plt0_got1_offset */
    1+8,				/* plt0_got2_offset */
    1+12,				/* plt0_got2_insn_end */
    4+1+2,				/* plt_got_offset */
    4+1,				/* plt_reloc_offset */
    4+1+6,				/* plt_plt_offset */
    4+1+6,				/* plt_got_insn_size */
    4+1+5+5,				/* plt_plt_insn_end */
    0,					/* plt_lazy_offset */
    elf_x86_64_lazy_bnd_plt0_entry,	/* pic_plt0_entry */
    elf_x86_64_lazy_bnd_ibt_plt_entry,	/* pic_plt_entry */
    elf_x86_64_eh_frame_lazy_bnd_ibt_plt, /* eh_frame_plt */
    sizeof (elf_x86_64_eh_frame_lazy_bnd_ibt_plt) /* eh_frame_plt_size */
  };

static const struct elf_x86_lazy_plt_layout elf_x86_64_lazy_ibt_plt =
  {
    elf_x86_64_lazy_plt0_entry,		/* plt0_entry */
    LAZY_PLT_ENTRY_SIZE,		/* plt0_entry_size */
    elf_x86_64_lazy_ibt_plt_entry,	/* plt_entry */
    LAZY_PLT_ENTRY_SIZE,		/* plt_entry_size */
    elf_x86_64_tlsdesc_plt_entry,	/* plt_tlsdesc_entry */
    LAZY_PLT_ENTRY_SIZE,		/* plt_tlsdesc_entry_size */
    6,					/* plt_tlsdesc_got1_offset */
    12,					/* plt_tlsdesc_got2_offset */
    10,					/* plt_tlsdesc_got1_insn_end */
    16,					/* plt_tlsdesc_got2_insn_end */
    2,					/* plt0_got1_offset */
    8,					/* plt0_got2_offset */
    12,					/* plt0_got2_insn_end */
    4+2,				/* plt_got_offset */
    4+1,				/* plt_reloc_offset */
    4+6,				/* plt_plt_offset */
    4+6,				/* plt_got_insn_size */
    4+5+5,				/* plt_plt_insn_end */
    0,					/* plt_lazy_offset */
    elf_x86_64_lazy_plt0_entry,		/* pic_plt0_entry */
    elf_x86_64_lazy_ibt_plt_entry,	/* pic_plt_entry */
    elf_x86_64_eh_frame_lazy_ibt_plt,	/* eh_frame_plt */
    sizeof (elf_x86_64_eh_frame_lazy_ibt_plt) /* eh_frame_plt_size */
  };

static const struct elf_x86_non_lazy_plt_layout elf_x86_64_non_lazy_bnd_ibt_plt =
  {
    elf_x86_64_non_lazy_bnd_ibt_plt_entry, /* plt_entry */
    elf_x86_64_non_lazy_bnd_ibt_plt_entry, /* pic_plt_entry */
    LAZY_PLT_ENTRY_SIZE,		/* plt_entry_size */
    4+1+2,				/* plt_got_offset */
    4+1+6,				/* plt_got_insn_size */
    elf_x86_64_eh_frame_non_lazy_plt,	/* eh_frame_plt */
    sizeof (elf_x86_64_eh_frame_non_lazy_plt) /* eh_frame_plt_size */
  };

static const struct elf_x86_non_lazy_plt_layout elf_x86_64_non_lazy_ibt_plt =
  {
    elf_x86_64_non_lazy_ibt_plt_entry,	/* plt_entry */
    elf_x86_64_non_lazy_ibt_plt_entry,	/* pic_plt_entry */
    LAZY_PLT_ENTRY_SIZE,		/* plt_entry_size */
    4+2,				/* plt_got_offset */
    4+6,				/* plt_got_insn_size */
    elf_x86_64_eh_frame_non_lazy_plt,	/* eh_frame_plt */
    sizeof (elf_x86_64_eh_frame_non_lazy_plt) /* eh_frame_plt_size */
  };

static bool elf64_x86_64_elf_object_p(bfd *abfd)
{
  if (abfd == NULL)
    return false;
  if (!bfd_default_set_arch_mach(abfd, bfd_arch_i386, bfd_mach_x86_64))
    return false;
  return true;
}

static bool elf32_x86_64_elf_object_p(bfd *abfd)
{
  if (!abfd)
    return false;
  if (!bfd_default_set_arch_mach(abfd, bfd_arch_i386, bfd_mach_x64_32))
    return false;
  return true;
}

/* Return TRUE if the TLS access code sequence support transition
   from R_TYPE.  */

static enum elf_x86_tls_error_type
elf_x86_64_check_tls_transition(bfd *abfd,
                               struct bfd_link_info *info,
                               asection *sec,
                               bfd_byte *contents,
                               Elf_Internal_Shdr *symtab_hdr,
                               struct elf_link_hash_entry **sym_hashes,
                               unsigned int r_type,
                               const Elf_Internal_Rela *rel,
                               const Elf_Internal_Rela *relend)
{
    unsigned int val;
    unsigned long r_symndx;
    bool largepic = false;
    struct elf_link_hash_entry *h;
    bfd_vma offset;
    struct elf_x86_link_hash_table *htab;
    bfd_byte *call;
    bool indirect_call;

    htab = elf_x86_hash_table(info, X86_64_ELF_DATA);
    offset = rel->r_offset;

    switch (r_type) {
    case R_X86_64_TLSGD:
    case R_X86_64_TLSLD: {
        static const unsigned char leaq[] = {0x66, 0x48, 0x8d, 0x3d};
        static const unsigned char lea[] = {0x48, 0x8d, 0x3d};
        bool is_tlsgd = (r_type == R_X86_64_TLSGD);

        if ((rel + 1) >= relend)
            return elf_x86_tls_error_yes;

        if (is_tlsgd) {
            if ((offset + 12) > sec->size)
                return elf_x86_tls_error_yes;

            call = contents + offset + 4;
            bool match1 = call[0] == 0x66 && call[1] == 0x48 && call[2] == 0xff && call[3] == 0x15;
            bool match2 = call[0] == 0x66 && call[1] == 0x48 && call[2] == 0x67 && call[3] == 0xe8;
            bool match3 = call[0] == 0x66 && call[1] == 0x66 && call[2] == 0x48 && call[3] == 0xe8;

            if (!(match1 || match2 || match3)) {
                if (!ABI_64_P(abfd) ||
                    (offset + 19) > sec->size ||
                    offset < 3 ||
                    memcmp(call - 7, leaq + 1, 3) != 0 ||
                    memcmp(call, "\x48\xb8", 2) != 0 ||
                    call[11] != 0x01 ||
                    call[13] != 0xff ||
                    call[14] != 0xd0 ||
                    !((call[10] == 0x48 && call[12] == 0xd8) || (call[10] == 0x4c && call[12] == 0xf8)))
                    return elf_x86_tls_error_yes;
                largepic = true;
            } else if (ABI_64_P(abfd)) {
                if (offset < 4 || memcmp(contents + offset - 4, leaq, 4) != 0)
                    return elf_x86_tls_error_yes;
            } else {
                if (offset < 3 || memcmp(contents + offset - 3, leaq + 1, 3) != 0)
                    return elf_x86_tls_error_yes;
            }
            indirect_call = call[2] == 0xff;
        } else {
            if (offset < 3 || (offset + 9) > sec->size)
                return elf_x86_tls_error_yes;
            if (memcmp(contents + offset - 3, lea, 3) != 0)
                return elf_x86_tls_error_yes;
            call = contents + offset + 4;

            if (!(call[0] == 0xe8 || (call[0] == 0xff && call[1] == 0x15) || (call[0] == 0x67 && call[1] == 0xe8))) {
                if (!ABI_64_P(abfd) ||
                    (offset + 19) > sec->size ||
                    memcmp(call, "\x48\xb8", 2) != 0 ||
                    call[11] != 0x01 ||
                    call[13] != 0xff ||
                    call[14] != 0xd0 ||
                    !((call[10] == 0x48 && call[12] == 0xd8) || (call[10] == 0x4c && call[12] == 0xf8)))
                    return elf_x86_tls_error_yes;
                largepic = true;
            }
            indirect_call = call[0] == 0xff;
        }

        r_symndx = htab->r_sym(rel[1].r_info);
        if (r_symndx < symtab_hdr->sh_info)
            return elf_x86_tls_error_yes;

        h = sym_hashes[r_symndx - symtab_hdr->sh_info];
        if (!h || !((struct elf_x86_link_hash_entry *)h)->tls_get_addr)
            return elf_x86_tls_error_yes;

        r_type = ELF32_R_TYPE(rel[1].r_info) & ~R_X86_64_converted_reloc_bit;
        if (largepic)
            return (r_type == R_X86_64_PLTOFF64) ? elf_x86_tls_error_none : elf_x86_tls_error_yes;
        if (indirect_call)
            return (r_type == R_X86_64_GOTPCRELX || r_type == R_X86_64_GOTPCREL) ? elf_x86_tls_error_none : elf_x86_tls_error_yes;
        return (r_type == R_X86_64_PC32 || r_type == R_X86_64_PLT32) ? elf_x86_tls_error_none : elf_x86_tls_error_yes;
    }

    case R_X86_64_CODE_4_GOTTPOFF:
        if (offset < 4 || (offset + 4) > sec->size)
            return elf_x86_tls_error_yes;
        if (!ABI_64_P(abfd) && contents[offset - 4] == 0x0f && contents[offset - 3] == 0x38 && contents[offset - 2] == 0x8b)
            goto check_gottpoff_modrm;
        if (contents[offset - 4] != 0xd5)
            return elf_x86_tls_error_yes;
        goto check_gottpoff;

    case R_X86_64_CODE_5_GOTTPOFF:
        if (offset < 5 || (offset + 4) > sec->size ||
            ((contents[offset - 5] | (ABI_64_P(abfd) ? 7 : 0xf)) != 0x4f) ||
            contents[offset - 4] != 0x0f ||
            contents[offset - 3] != 0x38 ||
            contents[offset - 2] != 0x8b)
            return elf_x86_tls_error_yes;
        goto check_gottpoff_modrm;

    case R_X86_64_CODE_6_GOTTPOFF:
        if (offset < 6 || (offset + 4) > sec->size || contents[offset - 6] != 0x62)
            return elf_x86_tls_error_yes;
        val = bfd_get_8(abfd, contents + offset - 2);
        if (val != 0x01 && val != 0x03 && val != 0x8b)
            return elf_x86_tls_error_add_movrs;
        goto check_gottpoff_modrm;

    case R_X86_64_GOTTPOFF:
        if (offset >= 3 && (offset + 4) <= sec->size) {
            val = bfd_get_8(abfd, contents + offset - 3);
            if (val != 0x48 && val != 0x4c) {
                if (ABI_64_P(abfd))
                    return elf_x86_tls_error_yes;
            }
        } else {
            if (ABI_64_P(abfd))
                return elf_x86_tls_error_yes;
            if (offset < 2 || (offset + 3) > sec->size)
                return elf_x86_tls_error_yes;
        }
check_gottpoff:
        val = bfd_get_8(abfd, contents + offset - 2);
        if (val != 0x8b && val != 0x03)
            return elf_x86_tls_error_add_mov;
check_gottpoff_modrm:
        val = bfd_get_8(abfd, contents + offset - 1);
        return ((val & 0xc7) == 5) ? elf_x86_tls_error_none : elf_x86_tls_error_yes;

    case R_X86_64_CODE_4_GOTPC32_TLSDESC:
        if (offset < 4 || (offset + 4) > sec->size || contents[offset - 4] != 0xd5)
            return elf_x86_tls_error_yes;
        goto check_tlsdesc;

    case R_X86_64_GOTPC32_TLSDESC:
        if (offset < 3 || (offset + 4) > sec->size)
            return elf_x86_tls_error_yes;
        val = bfd_get_8(abfd, contents + offset - 3);
        val &= 0xfb;
        if (val != 0x48 && (ABI_64_P(abfd) || val != 0x40))
            return elf_x86_tls_error_yes;
check_tlsdesc:
        if (bfd_get_8(abfd, contents + offset - 2) != 0x8d)
            return elf_x86_tls_error_lea;
        val = bfd_get_8(abfd, contents + offset - 1);
        return ((val & 0xc7) == 0x05) ? elf_x86_tls_error_none : elf_x86_tls_error_yes;

    case R_X86_64_TLSDESC_CALL:
        return elf_x86_tls_error_none;

    default:
        abort();
    }
}

/* Return TRUE if the TLS access transition is OK or no transition
   will be performed.  Update R_TYPE if there is a transition.  */

static bool
elf_x86_64_tls_transition(struct bfd_link_info *info, bfd *abfd,
                         asection *sec, bfd_byte *contents,
                         Elf_Internal_Shdr *symtab_hdr,
                         struct elf_link_hash_entry **sym_hashes,
                         unsigned int *r_type, int tls_type,
                         const Elf_Internal_Rela *rel,
                         const Elf_Internal_Rela *relend,
                         struct elf_link_hash_entry *h,
                         Elf_Internal_Sym *sym,
                         bool from_relocate_section)
{
    unsigned int from_type = *r_type;
    unsigned int to_type = from_type;
    bool check = true;
    bfd_vma offset;
    bfd_byte *call = NULL;
    enum elf_x86_tls_error_type tls_error;

    if (h && (h->type == STT_FUNC || h->type == STT_GNU_IFUNC))
        return true;

    switch (from_type) {
        case R_X86_64_TLSDESC_CALL:
            offset = rel->r_offset;
            if (offset + 2 <= sec->size) {
                unsigned int prefix = 0;
                call = contents + offset;
                if (!ABI_64_P(abfd)) {
                    if (call[0] == 0x67) {
                        prefix = 1;
                        if (offset + 3 > sec->size)
                            call = NULL;
                    }
                }
                if (call != NULL &&
                   (call[prefix] != 0xff || call[prefix + 1] != 0x10))
                    call = NULL;
            }
            if (!call) {
                _bfd_x86_elf_link_report_tls_transition_error(
                    info, abfd, sec, symtab_hdr, h, sym, rel,
                    "R_X86_64_TLSDESC_CALL", NULL,
                    elf_x86_tls_error_indirect_call);
                return false;
            }
            /* fallthrough */
        case R_X86_64_TLSGD:
        case R_X86_64_GOTPC32_TLSDESC:
        case R_X86_64_CODE_4_GOTPC32_TLSDESC:
        case R_X86_64_GOTTPOFF:
        case R_X86_64_CODE_4_GOTTPOFF:
        case R_X86_64_CODE_5_GOTTPOFF:
        case R_X86_64_CODE_6_GOTTPOFF:
            if (bfd_link_executable(info)) {
                to_type = (h == NULL) ? R_X86_64_TPOFF32 : R_X86_64_GOTTPOFF;
            }
            if (from_relocate_section) {
                unsigned int new_to_type = to_type;
                if (TLS_TRANSITION_IE_TO_LE_P(info, h, tls_type))
                    new_to_type = R_X86_64_TPOFF32;
                if (to_type == R_X86_64_TLSGD ||
                    to_type == R_X86_64_GOTPC32_TLSDESC ||
                    to_type == R_X86_64_CODE_4_GOTPC32_TLSDESC ||
                    to_type == R_X86_64_TLSDESC_CALL) {
                    if (tls_type == GOT_TLS_IE)
                        new_to_type = R_X86_64_GOTTPOFF;
                }
                check = (new_to_type != to_type &&
                        (from_type == to_type ||
                         (from_type >= R_X86_64_CODE_4_GOTTPOFF &&
                          from_type <= R_X86_64_CODE_6_GOTTPOFF &&
                          to_type == R_X86_64_GOTTPOFF)));
                to_type = new_to_type;
            }
            break;
        case R_X86_64_TLSLD:
            if (bfd_link_executable(info))
                to_type = R_X86_64_TPOFF32;
            break;
        default:
            return true;
    }

    if (from_type == to_type ||
        (from_type >= R_X86_64_CODE_4_GOTTPOFF && from_type <= R_X86_64_CODE_6_GOTTPOFF
         && to_type == R_X86_64_GOTTPOFF)) {
        return true;
    }

    if (check && ((tls_error = elf_x86_64_check_tls_transition(abfd, info, sec,
                                                              contents,
                                                              symtab_hdr,
                                                              sym_hashes,
                                                              from_type, rel,
                                                              relend))
                  != elf_x86_tls_error_none)) {
        reloc_howto_type *from = &x86_64_elf_howto_table[from_type];
        reloc_howto_type *to = &x86_64_elf_howto_table[to_type];
        if (!from || !to)
            return false;
        _bfd_x86_elf_link_report_tls_transition_error(
            info, abfd, sec, symtab_hdr, h, sym, rel, from->name,
            to->name, tls_error);
        return false;
    }

    *r_type = to_type;
    return true;
}

static bool elf_x86_64_need_pic(struct bfd_link_info *info,
                                bfd *input_bfd, asection *sec,
                                struct elf_link_hash_entry *h,
                                Elf_Internal_Shdr *symtab_hdr,
                                Elf_Internal_Sym *isym,
                                reloc_howto_type *howto)
{
    const char *visibility = "";
    const char *undef = "";
    const char *pic_hint = "";
    const char *object = NULL;
    const char *name = NULL;
    bool shared = bfd_link_dll(info);
    bool pie = bfd_link_pie(info);

    if (h) {
        name = h->root.root.string;
        switch (ELF_ST_VISIBILITY(h->other)) {
            case STV_HIDDEN:
                visibility = _("hidden symbol ");
                break;
            case STV_INTERNAL:
                visibility = _("internal symbol ");
                break;
            case STV_PROTECTED:
                visibility = _("protected symbol ");
                break;
            default:
                if (((struct elf_x86_link_hash_entry *) h)->def_protected)
                    visibility = _("protected symbol ");
                else
                    visibility = _("symbol ");
                pic_hint = NULL;
                break;
        }
        if (!SYMBOL_DEFINED_NON_SHARED_P(h) && !h->def_dynamic)
            undef = _("undefined ");
    } else {
        name = bfd_elf_sym_name(input_bfd, symtab_hdr, isym, NULL);
        pic_hint = NULL;
    }

    if (shared) {
        object = _("a shared object");
        if (!pic_hint)
            pic_hint = _("; recompile with -fPIC");
    } else {
        object = pie ? _("a PIE object") : _("a PDE object");
        if (!pic_hint)
            pic_hint = _("; recompile with -fPIE");
    }

    _bfd_error_handler(_("%pB: relocation %s against %s%s`%s' can "
                        "not be used when making %s%s"),
                      input_bfd, howto ? howto->name : "(unknown)", undef, visibility, name ? name : "(null)",
                      object ? object : "(null)", pic_hint ? pic_hint : "");

    bfd_set_error(bfd_error_bad_value);
    if (sec)
        sec->check_relocs_failed = 1;

    return false;
}

/* Move the R bits to the B bits in EVEX payload byte 1.  */
static unsigned int evex_move_r_to_b(unsigned int byte1, bool copy)
{
    unsigned int r3 = (byte1 >> 7) & 1;
    unsigned int r4 = (~byte1 >> 4) & 1;

    byte1 &= ~((1u << 5) | (1u << 3));
    byte1 |= (r3 << 5) | (r4 << 3);

    if (!copy)
        byte1 |= (1u << 4) | (1u << 7);

    return byte1;
}

/* With the local symbol, foo, we convert
   mov foo@GOTPCREL(%rip), %reg
   movrs foo@GOTPCREL(%rip), %reg
   to
   lea foo(%rip), %reg
   and convert
   call/jmp *foo@GOTPCREL(%rip)
   to
   nop call foo/jmp foo nop
   When PIC is false, convert
   test %reg, foo@GOTPCREL(%rip)
   to
   test $foo, %reg
   and convert
   push foo@GOTPCREL(%rip)
   to
   push $foo
   and convert
   binop foo@GOTPCREL(%rip), %reg
   to
   binop $foo, %reg
   where binop is one of adc, add, and, cmp, imul, or, sbb, sub, xor
   instructions.  */

static bool elf_x86_64_convert_load_reloc(
    bfd *abfd,
    asection *input_section,
    bfd_byte *contents,
    unsigned int *r_type_p,
    Elf_Internal_Rela *irel,
    struct elf_link_hash_entry *h,
    bool *converted,
    struct bfd_link_info *link_info)
{
    struct elf_x86_link_hash_table *htab;
    bool is_pic, no_overflow, relocx, is_branch = false,
         to_reloc_pc32, abs_symbol, local_ref;
    asection *tsec = NULL;
    bfd_signed_vma raddend;
    unsigned int opcode, modrm, r_type = *r_type_p, r_symndx;
    unsigned char evex[3] = {0, 0, 0};
    bfd_vma roff = irel->r_offset, abs_relocation;
    reloc_howto_type *howto;
    bfd_reloc_status_type r;
    Elf_Internal_Sym *isym;
    bfd_vma relocation;

    switch (r_type) {
    default:
        if (roff < 2) return true;
        relocx = (r_type == R_X86_64_GOTPCRELX);
        break;
    case R_X86_64_REX_GOTPCRELX:
        if (roff < 3) return true;
        relocx = true;
        break;
    case R_X86_64_CODE_4_GOTPCRELX:
        if (roff < 4) return true;
        opcode = bfd_get_8(abfd, contents + roff - 4);
        if (opcode != 0xd5 &&
            (opcode != 0x0f ||
             bfd_get_8(abfd, contents + roff - 3) != 0x38 ||
             bfd_get_8(abfd, contents + roff - 2) != 0x8b))
            return true;
        relocx = true;
        break;
    case R_X86_64_CODE_5_GOTPCRELX:
        if (roff < 5) return true;
        if ((bfd_get_8(abfd, contents + roff - 5) | 0xf) != 0x4f ||
            bfd_get_8(abfd, contents + roff - 4) != 0x0f ||
            bfd_get_8(abfd, contents + roff - 3) != 0x38 ||
            bfd_get_8(abfd, contents + roff - 2) != 0x8b)
            return true;
        relocx = true;
        break;
    case R_X86_64_CODE_6_GOTPCRELX:
        if (roff < 6) return true;
        if (bfd_get_8(abfd, contents + roff - 6) != 0x62) return true;
        evex[0] = bfd_get_8(abfd, contents + roff - 5);
        evex[1] = bfd_get_8(abfd, contents + roff - 4);
        evex[2] = bfd_get_8(abfd, contents + roff - 3);
        if ((evex[0] & 7) != 4 ||
            (evex[1] & 3) != 0 ||
            (evex[2] & 0xe0) != 0)
            return true;
        relocx = true;
        break;
    }

    raddend = irel->r_addend;
    if (raddend != -4) return true;
    htab = elf_x86_hash_table(link_info, X86_64_ELF_DATA);
    is_pic = bfd_link_pic(link_info);
    no_overflow = link_info->disable_target_specific_optimizations > 1;
    r_symndx = htab->r_sym(irel->r_info);

    opcode = bfd_get_8(abfd, contents + roff - 2);
    modrm = bfd_get_8(abfd, contents + roff - 1);
    if (opcode == 0xff) {
        switch (modrm & 0x38) {
        case 0x10:
        case 0x20:
            is_branch = true;
            break;
        case 0x30:
            break;
        default:
            return true;
        }
    }

    if (opcode != 0x8b) {
        if (!relocx) return true;
    }

    to_reloc_pc32 = (is_branch || !relocx || no_overflow || is_pic);

    abs_symbol = false;
    abs_relocation = 0;

    if (h == NULL) {
        isym = bfd_sym_from_r_symndx(&htab->elf.sym_cache, abfd, r_symndx);
        if (isym->st_shndx == SHN_UNDEF)
            return true;
        local_ref = true;
        if (isym->st_shndx == SHN_ABS) {
            tsec = bfd_abs_section_ptr;
            abs_symbol = true;
            abs_relocation = isym->st_value;
        } else if (isym->st_shndx == SHN_COMMON)
            tsec = bfd_com_section_ptr;
        else if (isym->st_shndx == SHN_X86_64_LCOMMON)
            tsec = &_bfd_elf_large_com_section;
        else
            tsec = bfd_section_from_elf_index(abfd, isym->st_shndx);
    } else {
        struct elf_x86_link_hash_entry *eh = elf_x86_hash_entry(h);
        isym = NULL;
        tsec = NULL;
        abs_symbol = ABS_SYMBOL_P(h);
        abs_relocation = h->root.u.def.value;
        local_ref = SYMBOL_REFERENCES_LOCAL_P(link_info, h);
        if ((relocx || opcode == 0x8b) &&
            (h->root.type == bfd_link_hash_undefweak && !eh->linker_def && local_ref)) {
            if (is_branch) {
                if (no_overflow) return true;
            } else if (relocx) {
                to_reloc_pc32 = false;
            }
            if (to_reloc_pc32 && is_pic)
                return true;
            goto convert;
        } else if (h->start_stop || eh->linker_def ||
                   ((h->def_regular || h->root.type == bfd_link_hash_defined ||
                     h->root.type == bfd_link_hash_defweak) &&
                    h != htab->elf.hdynamic && local_ref)) {
            if (h->start_stop || eh->linker_def ||
                (h->def_regular && (h->root.type == bfd_link_hash_new ||
                                    h->root.type == bfd_link_hash_undefined ||
                                    ((h->root.type == bfd_link_hash_defined ||
                                      h->root.type == bfd_link_hash_defweak) &&
                                     h->root.u.def.section == bfd_und_section_ptr)))) {
                if (no_overflow) return true;
                if (h->start_stop)
                    tsec = h->root.u.def.section;
                else if (h == htab->elf.hehdr_start) {
                    asection *sec;
                    tsec = NULL;
                    for (sec = link_info->output_bfd->sections;
                         sec != NULL;
                         sec = sec->next)
                        if ((sec->flags & SEC_LOAD) && (tsec == NULL || tsec->vma > sec->vma))
                            tsec = sec;
                }
                goto convert;
            }
            tsec = h->root.u.def.section;
        } else
            return true;
    }

    if (tsec == NULL)
        return false;

    if (elf_section_data(tsec) != NULL && (elf_section_flags(tsec) & SHF_X86_64_LARGE) != 0)
        return true;
    if (no_overflow) return true;

convert:
    if (h == NULL) {
        Elf_Internal_Rela rel = *irel;
        relocation = _bfd_elf_rela_local_sym(link_info->output_bfd, isym,
                                             &tsec, &rel);
        raddend = rel.r_addend;
    } else if (tsec != NULL)
        relocation = (h->root.u.def.value
                      + tsec->output_section->vma
                      + tsec->output_offset);
    else
        relocation = 0;

    if (is_branch) {
        unsigned int nop, disp;
        bfd_vma nop_offset;
        r_type = R_X86_64_PC32;
        howto = &x86_64_elf_howto_table[r_type];
        r = _bfd_final_link_relocate(howto, abfd, input_section,
                                     contents, irel->r_offset,
                                     relocation, raddend);
        if (r == bfd_reloc_overflow)
            return true;
        if (modrm == 0x25) {
            modrm = 0xe9;
            nop = NOP_OPCODE;
            nop_offset = irel->r_offset + 3;
            disp = bfd_get_32(abfd, contents + irel->r_offset);
            irel->r_offset -= 1;
            bfd_put_32(abfd, disp, contents + irel->r_offset);
        } else {
            struct elf_x86_link_hash_entry *eh = (struct elf_x86_link_hash_entry *)h;
            modrm = 0xe8;
            if (eh && eh->tls_get_addr) {
                nop = 0x67;
                nop_offset = irel->r_offset - 2;
            } else {
                nop = htab->params->call_nop_byte;
                if (htab->params->call_nop_as_suffix) {
                    nop_offset = irel->r_offset + 3;
                    disp = bfd_get_32(abfd, contents + irel->r_offset);
                    irel->r_offset -= 1;
                    bfd_put_32(abfd, disp, contents + irel->r_offset);
                } else
                    nop_offset = irel->r_offset - 2;
            }
        }
        bfd_put_8(abfd, nop, contents + nop_offset);
        bfd_put_8(abfd, modrm, contents + irel->r_offset - 1);
    } else if (r_type == R_X86_64_CODE_6_GOTPCRELX && opcode != 0x8b) {
        bool move_v_r = false;
        if (to_reloc_pc32)
            return true;
        if (opcode == 0x85) {
            modrm = 0xc0 | (modrm & 0x38) >> 3;
            opcode = 0xf7;
        } else if ((opcode | 0x3a) == 0x3b) {
            if (!(evex[2] & 0x10) && (opcode | 0x38) != 0x3b)
                return true;
            if ((evex[2] & 0x10) && (opcode | 0x38) != 0x3b &&
                (opcode == 0x19 || opcode == 0x29))
                return true;
            modrm = 0xc0 | ((modrm & 0x38) >> 3) | (opcode & 0x38);
            opcode = 0x81;
        } else if (opcode == 0xaf) {
            if (!(evex[2] & 0x10)) {
                modrm = 0xc0 | ((modrm & 0x38) >> 3) | (modrm & 0x38);
            } else {
                modrm = 0xc0 | ((modrm & 0x38) >> 3) | (~evex[1] & 0x38);
                move_v_r = true;
            }
            opcode = 0x69;
        } else
            return true;
        r_type = evex[1] & 0x80 ? R_X86_64_32S : R_X86_64_32;
        howto = elf_x86_64_rtype_to_howto(abfd, r_type);
        r = _bfd_final_link_relocate(howto, abfd, input_section,
                                     contents, irel->r_offset,
                                     relocation, 0);
        if (r == bfd_reloc_overflow)
            return true;
        if (abs_relocation) {
            if (r_type == R_X86_64_32S) {
                if ((abs_relocation + 0x80000000) > 0xffffffff)
                    return true;
            } else {
                if (abs_relocation > 0xffffffff)
                    return true;
            }
        }
        bfd_put_8(abfd, opcode, contents + roff - 2);
        bfd_put_8(abfd, modrm, contents + roff - 1);
        evex[0] = evex_move_r_to_b(evex[0], opcode == 0x69 && !move_v_r);
        if (move_v_r) {
            if (!(evex[1] & (1 << 6)))
                evex[0] &= ~(1 << 7);
            if (!(evex[2] & (1 << 3)))
                evex[0] &= ~(1 << 4);
            evex[1] |= 0xf << 3;
            evex[2] |= 1 << 3;
            evex[2] &= ~(1 << 4);
            bfd_put_8(abfd, evex[2], contents + roff - 3);
            bfd_put_8(abfd, evex[1], contents + roff - 4);
        }
        bfd_put_8(abfd, evex[0], contents + roff - 5);
        irel->r_addend = 0;
    } else {
        unsigned int rex = 0, rex_mask = REX_R,
                     rex2 = 0, rex2_mask = REX_R | REX_R << 4, movrs = 0;
        bool rex_w = false;
        if (r_type == R_X86_64_CODE_6_GOTPCRELX) {
            unsigned int p = bfd_get_8(abfd, contents + roff - 5);
            if (!(p & 0x80)) rex2 |= REX_R;
            if (!(p & 0x10)) rex2 |= REX_R << 4;
            if (bfd_get_8(abfd, contents + roff - 4) & 0x80) {
                rex2 |= REX_W;
                rex_w = true;
            }
            movrs = 6;
        } else if (r_type == R_X86_64_CODE_5_GOTPCRELX) {
            rex = bfd_get_8(abfd, contents + roff - 5);
            rex_w = (rex & REX_W) != 0;
            movrs = 5;
        } else if (r_type == R_X86_64_CODE_4_GOTPCRELX) {
            if (bfd_get_8(abfd, contents + roff - 4) == 0xd5) {
                rex2 = bfd_get_8(abfd, contents + roff - 3) | 0x100;
                rex2_mask |= 0x100;
                rex_w = (rex2 & REX_W) != 0;
            } else if (bfd_get_8(abfd, contents + roff - 4) == 0x0f)
                movrs = 4;
        } else if (r_type == R_X86_64_REX_GOTPCRELX) {
            rex = bfd_get_8(abfd, contents + roff - 3);
            rex_w = (rex & REX_W) != 0;
        }

        if (opcode == 0x8b) {
            if (abs_symbol && local_ref && relocx)
                to_reloc_pc32 = false;
            if (to_reloc_pc32) {
                opcode = 0x8d;
                r_type = R_X86_64_PC32;
                howto = &x86_64_elf_howto_table[r_type];
                r = _bfd_final_link_relocate(howto, abfd, input_section,
                                             contents, irel->r_offset,
                                             relocation, raddend);
                if (r == bfd_reloc_overflow)
                    return true;
                if (movrs == 5)
                    bfd_put_8(abfd, rex, contents + roff - 3);
            } else {
                opcode = 0xc7;
                modrm = 0xc0 | (modrm & 0x38) >> 3;
                if (rex_w && ABI_64_P(link_info->output_bfd)) {
                    r_type = R_X86_64_32S;
                    goto rewrite_modrm_rex;
                } else {
                    r_type = R_X86_64_32;
                    rex_mask |= REX_W;
                    rex2_mask |= REX_W;
                    goto rewrite_modrm_rex;
                }
            }
        } else {
            if (to_reloc_pc32)
                return true;
            if (opcode == 0x85 && !(rex2 & (REX2_M << 4))) {
                modrm = 0xc0 | (modrm & 0x38) >> 3;
                opcode = 0xf7;
            } else if ((opcode | 0x38) == 0x3b && !(rex2 & (REX2_M << 4))) {
                modrm = 0xc0 | ((modrm & 0x38) >> 3) | (opcode & 0x38);
                opcode = 0x81;
            } else if (opcode == 0xaf && (rex2 & (REX2_M << 4))) {
                modrm = 0xc0 | ((modrm & 0x38) >> 3) | (modrm & 0x38);
                rex_mask = 0;
                rex2_mask = REX2_M << 4;
                opcode = 0x69;
            } else if (opcode == 0xff && !(rex2 & (REX2_M << 4))) {
                bfd_put_8(abfd, 0x68, contents + roff - 1);
                if (rex) {
                    bfd_put_8(abfd, 0x2e, contents + roff - 3);
                    bfd_put_8(abfd, rex, contents + roff - 2);
                } else if (rex2) {
                    bfd_put_8(abfd, 0x2e, contents + roff - 4);
                    bfd_put_8(abfd, 0xd5, contents + roff - 3);
                    bfd_put_8(abfd, rex2, contents + roff - 2);
                } else
                    bfd_put_8(abfd, 0x2e, contents + roff - 2);
                r_type = R_X86_64_32S;
                irel->r_addend = 0;
                goto finish;
            } else
                return true;
            r_type = rex_w ? R_X86_64_32S : R_X86_64_32;
        rewrite_modrm_rex:
            howto = elf_x86_64_rtype_to_howto(abfd, r_type);
            r = _bfd_final_link_relocate(howto, abfd, input_section,
                                         contents, irel->r_offset,
                                         relocation, 0);
            if (r == bfd_reloc_overflow)
                return true;
            if (abs_relocation) {
                if (r_type == R_X86_64_32S) {
                    if ((abs_relocation + 0x80000000) > 0xffffffff)
                        return true;
                } else {
                    if (abs_relocation > 0xffffffff)
                        return true;
                }
            }
            bfd_put_8(abfd, modrm, contents + roff - 1);
            if (rex) {
                rex = (rex & ~rex_mask) | (rex & REX_R) >> 2;
                bfd_put_8(abfd, rex, contents + roff - 3);
            } else if (rex2) {
                rex2 = ((rex2 & ~rex2_mask) |
                        (rex2 & (REX_R | REX_R << 4)) >> 2);
                bfd_put_8(abfd, rex2, contents + roff - 3);
            }
            irel->r_addend = 0;
        }
        bfd_put_8(abfd, opcode, contents + roff - 2);
        if (movrs) {
            bfd_put_8(abfd, 0x2e, contents + roff - movrs);
            bfd_put_8(abfd, 0x2e, contents + roff - movrs + 1);
            if (movrs == 6) {
                bfd_put_8(abfd, 0xd5, contents + roff - 4);
                bfd_put_8(abfd, rex2, contents + roff - 3);
            }
        }
    }

finish:
    *r_type_p = r_type;
    irel->r_info = htab->r_info(r_symndx, r_type | R_X86_64_converted_reloc_bit);
    *converted = true;
    return true;
}

/* Look through the relocs for a section during the first phase, and
   calculate needed space in the global offset table, and procedure
   linkage table.  */

static bool elf_x86_64_scan_relocs(bfd *abfd, struct bfd_link_info *info, asection *sec, const Elf_Internal_Rela *relocs) {
    struct elf_x86_link_hash_table *htab;
    Elf_Internal_Shdr *symtab_hdr;
    struct elf_link_hash_entry **sym_hashes;
    const Elf_Internal_Rela *rel;
    const Elf_Internal_Rela *rel_end;
    bfd_byte *contents;
    bool converted = false;

    if (bfd_link_relocatable(info))
        return true;

    htab = elf_x86_hash_table(info, X86_64_ELF_DATA);
    if (!htab) {
        sec->check_relocs_failed = 1;
        return false;
    }

    BFD_ASSERT(is_x86_elf(abfd, htab));

    if (elf_section_data(sec)->this_hdr.contents)
        contents = elf_section_data(sec)->this_hdr.contents;
    else if (!_bfd_elf_mmap_section_contents(abfd, sec, &contents)) {
        sec->check_relocs_failed = 1;
        return false;
    }

    symtab_hdr = &elf_symtab_hdr(abfd);
    sym_hashes = elf_sym_hashes(abfd);

    rel_end = relocs + sec->reloc_count;
    for (rel = relocs; rel < rel_end; ++rel) {
        unsigned int r_type, r_symndx;
        struct elf_link_hash_entry *h = NULL;
        struct elf_x86_link_hash_entry *eh = NULL;
        Elf_Internal_Sym *isym = NULL;
        const char *name = NULL;
        bool size_reloc = false, converted_reloc = false, no_dynreloc = false;
        reloc_howto_type *howto;

        r_symndx = htab->r_sym(rel->r_info);
        r_type = ELF32_R_TYPE(rel->r_info);

        if (r_type == R_X86_64_NONE)
            continue;

        if (r_symndx >= NUM_SHDR_ENTRIES(symtab_hdr)) {
            _bfd_error_handler(_("%pB: bad symbol index: %d"), abfd, r_symndx);
            goto error_return;
        }

        howto = elf_x86_64_rtype_to_howto(abfd, r_type);
        if (!howto) {
            _bfd_error_handler(_("%pB: unsupported relocation type %#x"), abfd, r_type);
            goto error_return;
        }
        if (!bfd_reloc_offset_in_range(howto, abfd, sec, rel->r_offset)) {
            _bfd_error_handler(_("%pB: bad reloc offset (%#" PRIx64 " > %#" PRIx64 ") for section `%pA'"), abfd, (uint64_t)rel->r_offset, (uint64_t)sec->size, sec);
            goto error_return;
        }

        if (r_symndx < symtab_hdr->sh_info) {
            isym = bfd_sym_from_r_symndx(&htab->elf.sym_cache, abfd, r_symndx);
            if (!isym)
                goto error_return;

            if (ELF_ST_TYPE(isym->st_info) == STT_GNU_IFUNC) {
                h = _bfd_elf_x86_get_local_sym_hash(htab, abfd, rel, true);
                if (!h)
                    goto error_return;
                h->root.root.string = bfd_elf_sym_name(abfd, symtab_hdr, isym, NULL);
                h->type = STT_GNU_IFUNC;
                h->def_regular = 1;
                h->ref_regular = 1;
                h->forced_local = 1;
                h->root.type = bfd_link_hash_defined;
            }
        } else {
            h = _bfd_elf_get_link_hash_entry(sym_hashes, r_symndx, symtab_hdr);
        }

        if (!ABI_64_P(abfd)) {
            switch (r_type) {
                case R_X86_64_DTPOFF64:
                case R_X86_64_TPOFF64:
                case R_X86_64_PC64:
                case R_X86_64_GOTOFF64:
                case R_X86_64_GOT64:
                case R_X86_64_GOTPCREL64:
                case R_X86_64_GOTPC64:
                case R_X86_64_GOTPLT64:
                case R_X86_64_PLTOFF64:
                    name = h ? h->root.root.string : bfd_elf_sym_name(abfd, symtab_hdr, isym, NULL);
                    _bfd_error_handler(_("%pB: relocation %s against symbol `%s' isn't supported in x32 mode"), abfd, x86_64_elf_howto_table[r_type].name, name);
                    bfd_set_error(bfd_error_bad_value);
                    goto error_return;
                default:
                    break;
            }
        }

        eh = (struct elf_x86_link_hash_entry*)h;
        if (h)
            h->ref_regular = 1;

        if ((r_type == R_X86_64_GOTPCREL ||
             r_type == R_X86_64_GOTPCRELX ||
             r_type == R_X86_64_REX_GOTPCRELX ||
             r_type == R_X86_64_CODE_4_GOTPCRELX ||
             r_type == R_X86_64_CODE_5_GOTPCRELX ||
             r_type == R_X86_64_CODE_6_GOTPCRELX) &&
            (!h || h->type != STT_GNU_IFUNC)) {
            Elf_Internal_Rela *irel = (Elf_Internal_Rela*)rel;
            if (!elf_x86_64_convert_load_reloc(abfd, sec, contents, &r_type, irel, h, &converted_reloc, info))
                goto error_return;
            if (converted_reloc)
                converted = true;
        }

        if (!_bfd_elf_x86_valid_reloc_p(sec, info, htab, rel, h, isym, symtab_hdr, &no_dynreloc))
            goto error_return;

        if (!elf_x86_64_tls_transition(info, abfd, sec, contents, symtab_hdr, sym_hashes, &r_type, GOT_UNKNOWN, rel, rel_end, h, isym, false))
            goto error_return;

        if (h == htab->elf.hgot)
            htab->got_referenced = true;

        switch (r_type) {
            case R_X86_64_TLSLD:
                htab->tls_ld_or_ldm_got.refcount = 1;
                goto create_got;
            case R_X86_64_TPOFF32:
                if (!bfd_link_executable(info) && ABI_64_P(abfd)) {
                    elf_x86_64_need_pic(info, abfd, sec, h, symtab_hdr, isym, &x86_64_elf_howto_table[r_type]);
                    goto error_return;
                }
                if (eh)
                    eh->zero_undefweak &= 0x2;
                break;
            case R_X86_64_TLSDESC_CALL:
                htab->has_tls_desc_call = 1;
                goto need_got;
            case R_X86_64_GOTTPOFF:
            case R_X86_64_CODE_4_GOTTPOFF:
            case R_X86_64_CODE_5_GOTTPOFF:
            case R_X86_64_CODE_6_GOTTPOFF:
                if (!bfd_link_executable(info))
                    info->flags |= DF_STATIC_TLS;
            case R_X86_64_GOT32:
            case R_X86_64_GOTPCREL:
            case R_X86_64_GOTPCRELX:
            case R_X86_64_REX_GOTPCRELX:
            case R_X86_64_CODE_4_GOTPCRELX:
            case R_X86_64_CODE_5_GOTPCRELX:
            case R_X86_64_CODE_6_GOTPCRELX:
            case R_X86_64_TLSGD:
            case R_X86_64_GOT64:
            case R_X86_64_GOTPCREL64:
            case R_X86_64_GOTPLT64:
            case R_X86_64_GOTPC32_TLSDESC:
            case R_X86_64_CODE_4_GOTPC32_TLSDESC:
need_got: {
                int tls_type, old_tls_type;
                switch (r_type) {
                    default:
                        tls_type = GOT_NORMAL;
                        if (h && ABS_SYMBOL_P(h))
                            tls_type = GOT_ABS;
                        else if (!h && isym->st_shndx == SHN_ABS)
                            tls_type = GOT_ABS;
                        break;
                    case R_X86_64_TLSGD:
                        tls_type = GOT_TLS_GD;
                        break;
                    case R_X86_64_GOTTPOFF:
                    case R_X86_64_CODE_4_GOTTPOFF:
                    case R_X86_64_CODE_5_GOTTPOFF:
                    case R_X86_64_CODE_6_GOTTPOFF:
                        tls_type = GOT_TLS_IE;
                        break;
                    case R_X86_64_GOTPC32_TLSDESC:
                    case R_X86_64_CODE_4_GOTPC32_TLSDESC:
                    case R_X86_64_TLSDESC_CALL:
                        tls_type = GOT_TLS_GDESC;
                        break;
                }
                if (h) {
                    h->got.refcount = 1;
                    old_tls_type = eh->tls_type;
                } else {
                    if (!elf_x86_allocate_local_got_info(abfd, symtab_hdr->sh_info))
                        goto error_return;
                    elf_local_got_refcounts(abfd)[r_symndx] = 1;
                    old_tls_type = elf_x86_local_got_tls_type(abfd)[r_symndx];
                }
                if (old_tls_type != tls_type && old_tls_type != GOT_UNKNOWN && (!GOT_TLS_GD_ANY_P(old_tls_type) || tls_type != GOT_TLS_IE)) {
                    if (old_tls_type == GOT_TLS_IE && GOT_TLS_GD_ANY_P(tls_type))
                        tls_type = old_tls_type;
                    else if (GOT_TLS_GD_ANY_P(old_tls_type) && GOT_TLS_GD_ANY_P(tls_type))
                        tls_type |= old_tls_type;
                    else {
                        name = h ? h->root.root.string : bfd_elf_sym_name(abfd, symtab_hdr, isym, NULL);
                        _bfd_error_handler(_("%pB: '%s' accessed both as normal and thread local symbol"), abfd, name);
                        bfd_set_error(bfd_error_bad_value);
                        goto error_return;
                    }
                }
                if (old_tls_type != tls_type) {
                    if (eh)
                        eh->tls_type = tls_type;
                    else
                        elf_x86_local_got_tls_type(abfd)[r_symndx] = tls_type;
                }
            }
            case R_X86_64_GOTOFF64:
            case R_X86_64_GOTPC32:
            case R_X86_64_GOTPC64:
create_got:
                if (eh)
                    eh->zero_undefweak &= 0x2;
                break;
            case R_X86_64_PLT32:
                if (!h)
                    continue;
                eh->zero_undefweak &= 0x2;
                h->needs_plt = 1;
                h->plt.refcount = 1;
                break;
            case R_X86_64_PLTOFF64:
                if (h) {
                    h->needs_plt = 1;
                    h->plt.refcount = 1;
                }
                goto create_got;
            case R_X86_64_SIZE32:
            case R_X86_64_SIZE64:
                size_reloc = true;
                goto do_size;
            case R_X86_64_32:
                if (!ABI_64_P(abfd))
                    goto pointer;
            case R_X86_64_8:
            case R_X86_64_16:
            case R_X86_64_32S:
                if (!htab->params->no_reloc_overflow_check && !converted_reloc && (bfd_link_pic(info) || (bfd_link_executable(info) && h && !h->def_regular && h->def_dynamic && (sec->flags & SEC_READONLY) == 0))) {
                    elf_x86_64_need_pic(info, abfd, sec, h, symtab_hdr, isym, &x86_64_elf_howto_table[r_type]);
                    goto error_return;
                }
            case R_X86_64_PC8:
            case R_X86_64_PC16:
            case R_X86_64_PC32:
            case R_X86_64_PC64:
            case R_X86_64_64:
pointer:
                if (eh && (sec->flags & SEC_CODE))
                    eh->zero_undefweak |= 0x2;

                if (h && (bfd_link_executable(info) || h->type == STT_GNU_IFUNC)) {
                    bool func_pointer_ref = false;
                    if (r_type == R_X86_64_PC32) {
                        if ((sec->flags & SEC_CODE) == 0) {
                            h->pointer_equality_needed = 1;
                            if (bfd_link_pie(info) && h->type == STT_FUNC && !h->def_regular && h->def_dynamic) {
                                h->needs_plt = 1;
                                h->plt.refcount = 1;
                            }
                        }
                    } else if (r_type != R_X86_64_PC64) {
                        if ((sec->flags & SEC_READONLY) == 0 &&
                            (r_type == R_X86_64_64 || (!ABI_64_P(abfd) && (r_type == R_X86_64_32 || r_type == R_X86_64_32S))))
                            func_pointer_ref = true;
                        if (!func_pointer_ref || (bfd_link_pde(info) && h->type == STT_GNU_IFUNC))
                            h->pointer_equality_needed = 1;
                    }
                    if (!func_pointer_ref) {
                        h->non_got_ref = 1;
                        if (!elf_has_indirect_extern_access(sec->owner))
                            eh->non_got_ref_without_indirect_extern_access = 1;
                        if (!h->def_regular || (sec->flags & (SEC_CODE | SEC_READONLY)))
                            h->plt.refcount = 1;
                        if (htab->elf.target_os != is_solaris && h->pointer_equality_needed && h->type == STT_FUNC && eh->def_protected && !SYMBOL_DEFINED_NON_SHARED_P(h) && h->def_dynamic) {
                            _bfd_error_handler(_("%pB: non-canonical reference to canonical protected function `%s' in %pB"), abfd, h->root.root.string, h->root.u.def.section->owner);
                            bfd_set_error(bfd_error_bad_value);
                            goto error_return;
                        }
                    }
                }
                size_reloc = false;
do_size:
                if (!no_dynreloc && NEED_DYNAMIC_RELOCATION_P(true, info, true, h, sec, r_type, htab->pointer_r_type)) {
                    struct elf_dyn_relocs **head, *p;
                    if (h)
                        head = &h->dyn_relocs;
                    else {
                        asection *s = NULL;
                        void **vpp;
                        isym = bfd_sym_from_r_symndx(&htab->elf.sym_cache, abfd, r_symndx);
                        if (!isym)
                            goto error_return;
                        s = bfd_section_from_elf_index(abfd, isym->st_shndx);
                        if (!s)
                            s = sec;
                        vpp = &(elf_section_data(s)->local_dynrel);
                        head = (struct elf_dyn_relocs **)vpp;
                    }
                    p = *head;
                    if (!p || p->sec != sec) {
                        p = (struct elf_dyn_relocs*)bfd_alloc(htab->elf.dynobj, sizeof *p);
                        if (!p)
                            goto error_return;
                        p->next = *head;
                        *head = p;
                        p->sec = sec;
                        p->count = 0;
                        p->pc_count = 0;
                    }
                    p->count += 1;
                    if (X86_PCREL_TYPE_P(true, r_type) || size_reloc)
                        p->pc_count += 1;
                }
                break;
            case R_X86_64_CODE_5_GOTPC32_TLSDESC:
            case R_X86_64_CODE_6_GOTPC32_TLSDESC:
                name = h ? h->root.root.string : bfd_elf_sym_name(abfd, symtab_hdr, isym, NULL);
                _bfd_error_handler(_("%pB: unsupported relocation %s against symbol `%s'"), abfd, x86_64_elf_howto_table[r_type].name, name);
                break;
            case R_X86_64_GNU_VTINHERIT:
                if (!bfd_elf_gc_record_vtinherit(abfd, sec, h, rel->r_offset))
                    goto error_return;
                break;
            case R_X86_64_GNU_VTENTRY:
                if (!bfd_elf_gc_record_vtentry(abfd, sec, h, rel->r_addend))
                    goto error_return;
                break;
            default:
                break;
        }
    }

    if (elf_section_data(sec)->this_hdr.contents != contents) {
        if (!converted)
            _bfd_elf_munmap_section_contents(sec, contents);
        else {
            elf_section_data(sec)->this_hdr.contents = contents;
            info->cache_size += sec->size;
        }
    }

    if (elf_section_data(sec)->relocs != relocs && converted)
        elf_section_data(sec)->relocs = (Elf_Internal_Rela*)relocs;

    return true;

error_return:
    if (elf_section_data(sec)->this_hdr.contents != contents)
        _bfd_elf_munmap_section_contents(sec, contents);
    sec->check_relocs_failed = 1;
    return false;
}

static bool elf_x86_64_early_size_sections(bfd *output_bfd, struct bfd_link_info *info)
{
    if (!output_bfd || !info)
        return false;

    for (bfd *abfd = info->input_bfds; abfd != NULL; abfd = abfd->link.next) {
        if (bfd_get_flavour(abfd) != bfd_target_elf_flavour)
            continue;
        if (!_bfd_elf_link_iterate_on_relocs(abfd, info, elf_x86_64_scan_relocs))
            return false;
    }

    return _bfd_x86_elf_early_size_sections(output_bfd, info);
}

/* Return the relocation value for @tpoff relocation
   if STT_TLS virtual address is ADDRESS.  */

static bfd_vma elf_x86_64_tpoff(struct bfd_link_info *info, bfd_vma address) {
    if (!info) return 0;
    struct elf_link_hash_table *htab = elf_hash_table(info);
    if (!htab || !info->output_bfd) return 0;
    const struct elf_backend_data *bed = get_elf_backend_data(info->output_bfd);
    if (!bed) return 0;
    if (!htab->tls_sec) return 0;
    bfd_vma static_tls_size = BFD_ALIGN(htab->tls_size, bed->static_tls_alignment);
    return address - static_tls_size - htab->tls_sec->vma;
}

/* Relocate an x86_64 ELF section.  */

static int elf_x86_64_relocate_section (
    bfd *output_bfd,
    struct bfd_link_info *info,
    bfd *input_bfd,
    asection *input_section,
    bfd_byte *contents,
    Elf_Internal_Rela *relocs,
    Elf_Internal_Sym *local_syms,
    asection **local_sections
)
{
    struct elf_x86_link_hash_table *htab;
    Elf_Internal_Shdr *symtab_hdr;
    struct elf_link_hash_entry **sym_hashes;
    bfd_vma *local_got_offsets;
    bfd_vma *local_tlsdesc_gotents;
    Elf_Internal_Rela *rel, *wrel, *relend;
    unsigned int plt_entry_size;
    bool status = true;

    if (input_section->check_relocs_failed)
        return false;

    htab = elf_x86_hash_table(info, X86_64_ELF_DATA);
    if (!htab)
        return false;

    if (!is_x86_elf(input_bfd, htab)) {
        bfd_set_error(bfd_error_wrong_format);
        return false;
    }

    plt_entry_size = htab->plt.plt_entry_size;
    symtab_hdr = &elf_symtab_hdr(input_bfd);
    sym_hashes = elf_sym_hashes(input_bfd);
    local_got_offsets = elf_local_got_offsets(input_bfd);
    local_tlsdesc_gotents = elf_x86_local_tlsdesc_gotent(input_bfd);
    _bfd_x86_elf_set_tls_module_base(info);

    rel = wrel = relocs;
    relend = relocs + input_section->reloc_count;

    for (; rel < relend; wrel++, rel++) {
        unsigned int r_type, r_type_tls;
        reloc_howto_type *howto;
        unsigned long r_symndx;
        struct elf_link_hash_entry *h = NULL;
        struct elf_x86_link_hash_entry *eh = NULL;
        Elf_Internal_Sym *sym = NULL;
        asection *sec = NULL;
        bfd_vma off = 0, offplt = 0, plt_offset = 0, relocation = 0, st_size = 0;
        bool unresolved_reloc = false, resolved_to_zero = false, relative_reloc = false;
        bool converted_reloc = false, need_copy_reloc_in_pie = false, no_copyreloc_p = false;
        bfd_reloc_status_type r;
        int tls_type = GOT_UNKNOWN;
        asection *base_got = NULL, *resolved_plt = NULL;

        r_type = ELF32_R_TYPE(rel->r_info);
        if (r_type == (int)R_X86_64_GNU_VTINHERIT || r_type == (int)R_X86_64_GNU_VTENTRY) {
            if (wrel != rel)
                *wrel = *rel;
            continue;
        }

        r_symndx = htab->r_sym(rel->r_info);
        converted_reloc = (r_type & R_X86_64_converted_reloc_bit) != 0;
        if (converted_reloc) {
            r_type &= ~R_X86_64_converted_reloc_bit;
            rel->r_info = htab->r_info(r_symndx, r_type);
        }

        howto = elf_x86_64_rtype_to_howto(input_bfd, r_type);
        if (!howto)
            return _bfd_unrecognized_reloc(input_bfd, input_section, r_type);

        if (r_symndx < symtab_hdr->sh_info) {
            sym = local_syms + r_symndx;
            sec = local_sections[r_symndx];
            relocation = _bfd_elf_rela_local_sym(output_bfd, sym, &sec, rel);
            st_size = sym->st_size;

            if (!bfd_link_relocatable(info) && ELF_ST_TYPE(sym->st_info) == STT_GNU_IFUNC) {
                h = _bfd_elf_x86_get_local_sym_hash(htab, input_bfd, rel, false);
                if (!h)
                    abort();
                h->root.u.def.value = sym->st_value;
                h->root.u.def.section = sec;
            }
        } else {
            bool warned ATTRIBUTE_UNUSED = false;
            bool ignored ATTRIBUTE_UNUSED = false;
            RELOC_FOR_GLOBAL_SYMBOL(info, input_bfd, input_section, rel,
                r_symndx, symtab_hdr, sym_hashes, h, sec, relocation,
                unresolved_reloc, warned, ignored);
            st_size = h ? h->size : 0;
        }

        if (sec && discarded_section(sec)) {
            _bfd_clear_contents(howto, input_bfd, input_section, contents, rel->r_offset);
            wrel->r_offset = rel->r_offset;
            wrel->r_info = 0;
            wrel->r_addend = 0;

            if (bfd_link_relocatable(info) &&
                ((input_section->flags & SEC_DEBUGGING) != 0 ||
                 elf_section_type(input_section) == SHT_GNU_SFRAME))
                wrel--;

            continue;
        }

        if (bfd_link_relocatable(info)) {
            if (wrel != rel)
                *wrel = *rel;
            continue;
        }

        if (rel->r_addend == 0 && !ABI_64_P(output_bfd)) {
            if (r_type == R_X86_64_64) {
                r_type = R_X86_64_32;
                memset(contents + rel->r_offset + 4, 0, 4);
            } else if (r_type == R_X86_64_SIZE64) {
                r_type = R_X86_64_SIZE32;
                memset(contents + rel->r_offset + 4, 0, 4);
            }
        }

        eh = (struct elf_x86_link_hash_entry *)h;

        if (h && h->type == STT_GNU_IFUNC && h->def_regular) {
            bfd_vma plt_index;
            const char *name;
            if ((input_section->flags & SEC_ALLOC) == 0) {
                if (elf_section_type(input_section) == SHT_NOTE)
                    goto skip_ifunc;
                if ((input_section->flags & SEC_DEBUGGING) != 0)
                    continue;
                abort();
            }

            switch (r_type) {
            case R_X86_64_GOTPCREL:
            case R_X86_64_GOTPCRELX: case R_X86_64_REX_GOTPCRELX:
            case R_X86_64_CODE_4_GOTPCRELX: case R_X86_64_CODE_5_GOTPCRELX:
            case R_X86_64_CODE_6_GOTPCRELX: case R_X86_64_GOTPCREL64:
                base_got = htab->elf.sgot;
                off = h->got.offset;
                if (!base_got) abort();
                if (off == (bfd_vma)-1) {
                    if (h->plt.offset == (bfd_vma)-1) abort();
                    if (htab->elf.splt) {
                        plt_index = (h->plt.offset / plt_entry_size - htab->plt.has_plt0);
                        off = (plt_index + 3) * GOT_ENTRY_SIZE;
                        base_got = htab->elf.sgotplt;
                    } else {
                        plt_index = h->plt.offset / plt_entry_size;
                        off = plt_index * GOT_ENTRY_SIZE;
                        base_got = htab->elf.igotplt;
                    }
                    if (h->dynindx == -1 || h->forced_local || info->symbolic) {
                        if ((off & 1) != 0)
                            off &= ~1;
                        else {
                            bfd_put_64(output_bfd, relocation, base_got->contents + off);
                            h->got.offset |= 1;
                        }
                    }
                }
                relocation = base_got->output_section->vma +
                             base_got->output_offset + off;
                goto do_relocation;
            default: break;
            }

            if (h->plt.offset == (bfd_vma)-1) {
                if (r_type == htab->pointer_r_type && (input_section->flags & SEC_CODE) == 0)
                    goto do_ifunc_pointer;
                goto bad_ifunc_reloc;
            }
            if (htab->elf.splt) {
                if (htab->plt_second) {
                    resolved_plt = htab->plt_second;
                    plt_offset = eh->plt_second.offset;
                } else {
                    resolved_plt = htab->elf.splt;
                    plt_offset = h->plt.offset;
                }
            } else {
                resolved_plt = htab->elf.iplt;
                plt_offset = h->plt.offset;
            }
            relocation = resolved_plt->output_section->vma +
                         resolved_plt->output_offset + plt_offset;

            switch (r_type) {
            default:
            bad_ifunc_reloc:
                name = h->root.root.string ? h->root.root.string :
                    bfd_elf_sym_name(input_bfd, symtab_hdr, sym, NULL);
                _bfd_error_handler(
                    _("%pB: relocation %s against STT_GNU_IFUNC symbol `%s' isn't supported"),
                    input_bfd, howto->name, name);
                bfd_set_error(bfd_error_bad_value);
                return false;
            case R_X86_64_32S:
                if (bfd_link_pic(info))
                    abort();
                goto do_relocation;
            case R_X86_64_32:
                if (ABI_64_P(output_bfd))
                    goto do_relocation;
            case R_X86_64_64:
            do_ifunc_pointer:
                if (rel->r_addend != 0) {
                    name = h->root.root.string ?
                           h->root.root.string :
                           bfd_elf_sym_name(input_bfd, symtab_hdr, sym, NULL);
                    _bfd_error_handler(
                        _("%pB: relocation %s against STT_GNU_IFUNC symbol `%s' has non-zero addend: %" PRId64),
                        input_bfd, howto->name, name, (int64_t)rel->r_addend);
                    bfd_set_error(bfd_error_bad_value);
                    return false;
                }
                if ((bfd_link_pic(info) && h->non_got_ref) ||
                    h->plt.offset == (bfd_vma)-1)
                {
                    Elf_Internal_Rela outrel;
                    asection *sreloc;
                    outrel.r_offset = _bfd_elf_section_offset(output_bfd, info, input_section, rel->r_offset);
                    if (outrel.r_offset == (bfd_vma)-1 || outrel.r_offset == (bfd_vma)-2)
                        abort();
                    outrel.r_offset += input_section->output_section->vma + input_section->output_offset;
                    if (POINTER_LOCAL_IFUNC_P(info, h)) {
                        info->callbacks->minfo(
                            _("Local IFUNC function `%s' in %pB\n"),
                            h->root.root.string,
                            h->root.u.def.section->owner);
                        outrel.r_info = htab->r_info(0, R_X86_64_IRELATIVE);
                        outrel.r_addend = h->root.u.def.value +
                            h->root.u.def.section->output_section->vma +
                            h->root.u.def.section->output_offset;
                        if (htab->params->report_relative_reloc)
                            _bfd_x86_elf_link_report_relative_reloc(
                                info, input_section, h, sym, "R_X86_64_IRELATIVE", &outrel);
                    } else {
                        outrel.r_info = htab->r_info(h->dynindx, r_type);
                        outrel.r_addend = 0;
                    }
                    if (bfd_link_pic(info))
                        sreloc = htab->elf.irelifunc;
                    else if (htab->elf.splt)
                        sreloc = htab->elf.srelgot;
                    else
                        sreloc = htab->elf.irelplt;
                    elf_append_rela(output_bfd, sreloc, &outrel);
                    continue;
                }
            case R_X86_64_PC32: case R_X86_64_PC64: case R_X86_64_PLT32:
                goto do_relocation;
            }
        }

    skip_ifunc:
        resolved_to_zero = (eh && UNDEFINED_WEAK_RESOLVED_TO_ZERO(info, eh));

        switch (r_type) {
        case R_X86_64_GOT32: case R_X86_64_GOT64:
        case R_X86_64_GOTPCREL: case R_X86_64_GOTPCRELX: case R_X86_64_REX_GOTPCRELX:
        case R_X86_64_CODE_4_GOTPCRELX: case R_X86_64_CODE_5_GOTPCRELX:
        case R_X86_64_CODE_6_GOTPCRELX: case R_X86_64_GOTPCREL64:
        case R_X86_64_GOTPLT64:
            base_got = htab->elf.sgot;
            if (!htab->elf.sgot) abort();
            relative_reloc = false;
            if (h) {
                off = h->got.offset;
                if (h->needs_plt && h->plt.offset != (bfd_vma)-1 && off == (bfd_vma)-1) {
                    bfd_vma plt_index = (h->plt.offset / plt_entry_size - htab->plt.has_plt0);
                    off = (plt_index + 3) * GOT_ENTRY_SIZE;
                    base_got = htab->elf.sgotplt;
                }
                if (RESOLVED_LOCALLY_P(info, h, htab)) {
                    if ((off & 1) != 0)
                        off &= ~1;
                    else {
                        bfd_put_64(output_bfd, relocation, base_got->contents + off);
                        h->got.offset |= 1;
                        if (!info->enable_dt_relr && GENERATE_RELATIVE_RELOC_P(info, h)) {
                            eh->no_finish_dynamic_symbol = 1;
                            relative_reloc = true;
                        }
                    }
                } else {
                    unresolved_reloc = false;
                }
            } else {
                if (!local_got_offsets)
                    abort();
                off = local_got_offsets[r_symndx];
                if ((off & 1) != 0)
                    off &= ~1;
                else {
                    bfd_put_64(output_bfd, relocation, base_got->contents + off);
                    local_got_offsets[r_symndx] |= 1;
                    if (!info->enable_dt_relr && bfd_link_pic(info) &&
                        !(sym->st_shndx == SHN_ABS &&
                          (r_type == R_X86_64_GOTPCREL ||
                           r_type == R_X86_64_GOTPCRELX ||
                           r_type == R_X86_64_REX_GOTPCRELX ||
                           r_type == R_X86_64_CODE_4_GOTPCRELX ||
                           r_type == R_X86_64_CODE_5_GOTPCRELX ||
                           r_type == R_X86_64_CODE_6_GOTPCRELX)))
                        relative_reloc = true;
                }
            }
            if (relative_reloc) {
                asection *s;
                Elf_Internal_Rela outrel;
                s = htab->elf.srelgot;
                if (!s) abort();
                outrel.r_offset = base_got->output_section->vma +
                                  base_got->output_offset + off;
                outrel.r_info = htab->r_info(0, R_X86_64_RELATIVE);
                outrel.r_addend = relocation;
                if (htab->params->report_relative_reloc)
                    _bfd_x86_elf_link_report_relative_reloc(
                        info, input_section, h, sym, "R_X86_64_RELATIVE", &outrel);
                elf_append_rela(output_bfd, s, &outrel);
            }
            if (off >= (bfd_vma)-2) abort();
            relocation = base_got->output_section->vma + base_got->output_offset + off;
            if (r_type != R_X86_64_GOTPCREL &&
                r_type != R_X86_64_GOTPCRELX &&
                r_type != R_X86_64_REX_GOTPCRELX &&
                r_type != R_X86_64_CODE_4_GOTPCRELX &&
                r_type != R_X86_64_CODE_5_GOTPCRELX &&
                r_type != R_X86_64_CODE_6_GOTPCRELX &&
                r_type != R_X86_64_GOTPCREL64)
                relocation -= htab->elf.sgotplt->output_section->vma -
                              htab->elf.sgotplt->output_offset;
            break;
        case R_X86_64_GOTOFF64:
            if (bfd_link_pic(info) && h) {
                if (!h->def_regular) {
                    const char *v;
                    switch (ELF_ST_VISIBILITY(h->other)) {
                        case STV_HIDDEN: v = _("hidden symbol"); break;
                        case STV_INTERNAL: v = _("internal symbol"); break;
                        case STV_PROTECTED: v = _("protected symbol"); break;
                        default: v = _("symbol"); break;
                    }
                    _bfd_error_handler(
                        _("%pB: relocation R_X86_64_GOTOFF64 against undefined %s `%s' can not be used when making a shared object"),
                        input_bfd, v, h->root.root.string);
                    bfd_set_error(bfd_error_bad_value);
                    return false;
                } else if (!bfd_link_executable(info) &&
                           !SYMBOL_REFERENCES_LOCAL_P(info, h) &&
                           (h->type == STT_FUNC || h->type == STT_OBJECT) &&
                           ELF_ST_VISIBILITY(h->other) == STV_PROTECTED) {
                    _bfd_error_handler(
                        _("%pB: relocation R_X86_64_GOTOFF64 against protected %s `%s' can not be used when making a shared object"),
                        input_bfd, h->type == STT_FUNC ? "function" : "data",
                        h->root.root.string);
                    bfd_set_error(bfd_error_bad_value);
                    return false;
                }
            }
            relocation -= htab->elf.sgotplt->output_section->vma +
                          htab->elf.sgotplt->output_offset;
            break;
        case R_X86_64_GOTPC32: case R_X86_64_GOTPC64:
            relocation = htab->elf.sgotplt->output_section->vma +
                         htab->elf.sgotplt->output_offset;
            unresolved_reloc = false;
            break;
        case R_X86_64_PLTOFF64:
            if (h && (h->plt.offset != (bfd_vma)-1 ||
                      eh->plt_got.offset != (bfd_vma)-1)
                && htab->elf.splt) {
                if (eh->plt_got.offset != (bfd_vma)-1) {
                    resolved_plt = htab->plt_got;
                    plt_offset = eh->plt_got.offset;
                } else if (htab->plt_second) {
                    resolved_plt = htab->plt_second;
                    plt_offset = eh->plt_second.offset;
                } else {
                    resolved_plt = htab->elf.splt;
                    plt_offset = h->plt.offset;
                }
                relocation = resolved_plt->output_section->vma +
                             resolved_plt->output_offset + plt_offset;
                unresolved_reloc = false;
            }
            relocation -= htab->elf.sgotplt->output_section->vma +
                          htab->elf.sgotplt->output_offset;
            break;
        case R_X86_64_PLT32:
            if (!h) break;
            if ((h->plt.offset == (bfd_vma)-1 && eh->plt_got.offset == (bfd_vma)-1) ||
                htab->elf.splt == NULL)
                break;
use_plt:
            if (h->plt.offset != (bfd_vma)-1) {
                if (htab->plt_second) {
                    resolved_plt = htab->plt_second;
                    plt_offset = eh->plt_second.offset;
                } else {
                    resolved_plt = htab->elf.splt;
                    plt_offset = h->plt.offset;
                }
            } else {
                resolved_plt = htab->plt_got;
                plt_offset = eh->plt_got.offset;
            }
            relocation = resolved_plt->output_section->vma +
                         resolved_plt->output_offset + plt_offset;
            unresolved_reloc = false;
            break;
        case R_X86_64_SIZE32: case R_X86_64_SIZE64:
            relocation = st_size;
            goto direct;
        case R_X86_64_PC8: case R_X86_64_PC16: case R_X86_64_PC32:
            no_copyreloc_p = (info->nocopyreloc ||
                (h && !h->root.linker_def && !h->root.ldscript_def && eh->def_protected));
            if ((input_section->flags & SEC_ALLOC) &&
                (input_section->flags & SEC_READONLY) && h &&
                ((bfd_link_executable(info) && (
                    (h->root.type == bfd_link_hash_undefweak &&
                     (!eh || !UNDEFINED_WEAK_RESOLVED_TO_ZERO(info, eh))) ||
                    (bfd_link_pie(info) &&
                     !SYMBOL_DEFINED_NON_SHARED_P(h) && h->def_dynamic) ||
                    (no_copyreloc_p && h->def_dynamic &&
                     !(h->root.u.def.section->flags & SEC_CODE))))
                 || (bfd_link_pie(info) && h->root.type == bfd_link_hash_undefweak)
                 || bfd_link_dll(info))) {
                bool fail = false;
                if (SYMBOL_REFERENCES_LOCAL_P(info, h)) {
                    fail = !SYMBOL_DEFINED_NON_SHARED_P(h);
                } else if (bfd_link_pie(info)) {
                    if (h->root.type == bfd_link_hash_undefweak ||
                        (h->type == STT_FUNC && (sec->flags & SEC_CODE)))
                        fail = true;
                } else if (no_copyreloc_p || bfd_link_dll(info)) {
                    fail = (ELF_ST_VISIBILITY(h->other) == STV_DEFAULT ||
                            ELF_ST_VISIBILITY(h->other) == STV_PROTECTED);
                }
                if (fail)
                    return elf_x86_64_need_pic(info, input_bfd, input_section,
                                              h, NULL, NULL, howto);
            } else if (h && (input_section->flags & SEC_CODE) == 0 &&
                       bfd_link_pie(info) && h->type == STT_FUNC &&
                       !h->def_regular && h->def_dynamic)
                goto use_plt;
        case R_X86_64_8: case R_X86_64_16: case R_X86_64_32:
        case R_X86_64_PC64: case R_X86_64_64:
direct:
            if ((input_section->flags & SEC_ALLOC) == 0)
                break;
            need_copy_reloc_in_pie = (bfd_link_pie(info) && h &&
                (h->needs_copy || (eh && eh->needs_copy) ||
                 (h->root.type == bfd_link_hash_undefined)) &&
                (X86_PCREL_TYPE_P(true, r_type) || X86_SIZE_TYPE_P(true, r_type)));
            if (GENERATE_DYNAMIC_RELOCATION_P(true, info, eh, r_type, sec,
                                              need_copy_reloc_in_pie,
                                              resolved_to_zero, false)) {
                Elf_Internal_Rela outrel;
                bool skip = false, relocate = false, generate_dynamic_reloc = true;
                const char *relative_reloc_name = NULL;
                asection *sreloc;
                outrel.r_offset = _bfd_elf_section_offset(output_bfd, info, input_section, rel->r_offset);
                if (outrel.r_offset == (bfd_vma)-1)
                    skip = true;
                else if (outrel.r_offset == (bfd_vma)-2)
                    skip = true, relocate = true;
                outrel.r_offset += input_section->output_section->vma + input_section->output_offset;
                if (skip)
                    memset(&outrel, 0, sizeof outrel);
                else if (COPY_INPUT_RELOC_P(true, info, h, r_type)) {
                    outrel.r_info = htab->r_info(h->dynindx, r_type);
                    outrel.r_addend = rel->r_addend;
                } else {
                    long sindx;
                    if (r_type == htab->pointer_r_type ||
                        (r_type == R_X86_64_32 && htab->params->no_reloc_overflow_check)) {
                        relocate = true;
                        if (info->enable_dt_relr)
                            generate_dynamic_reloc = false;
                        else {
                            outrel.r_info = htab->r_info(0, R_X86_64_RELATIVE);
                            outrel.r_addend = relocation + rel->r_addend;
                            relative_reloc_name = "R_X86_64_RELATIVE";
                        }
                    } else if (r_type == R_X86_64_64 && !ABI_64_P(output_bfd)) {
                        relocate = true;
                        outrel.r_info = htab->r_info(0, R_X86_64_RELATIVE64);
                        outrel.r_addend = relocation + rel->r_addend;
                        relative_reloc_name = "R_X86_64_RELATIVE64";
                        if ((outrel.r_addend & 0x80000000) != (rel->r_addend & 0x80000000)) {
                            const char *name;
                            int addend = rel->r_addend;
                            name = h && h->root.root.string ?
                                   h->root.root.string :
                                   bfd_elf_sym_name(input_bfd, symtab_hdr,
                                                    sym, NULL);
                            _bfd_error_handler(
                                _("%pB: addend %s%#x in relocation %s against symbol `%s' at %#" PRIx64
                                  " in section `%pA' is out of range"),
                                input_bfd, addend < 0 ? "-" : "", addend,
                                howto->name, name, (uint64_t) rel->r_offset, input_section);
                            bfd_set_error(bfd_error_bad_value);
                            return false;
                        }
                    } else {
                        if (bfd_is_abs_section(sec))
                            sindx = 0;
                        else if (!sec || !sec->owner) {
                            bfd_set_error(bfd_error_bad_value);
                            return false;
                        } else {
                            asection *osec = sec->output_section;
                            sindx = elf_section_data(osec)->dynindx;
                            if (sindx == 0)
                                sindx = elf_section_data(htab->elf.text_index_section)->dynindx;
                            BFD_ASSERT(sindx != 0);
                        }
                        outrel.r_info = htab->r_info(sindx, r_type);
                        outrel.r_addend = relocation + rel->r_addend;
                    }
                }
                if (generate_dynamic_reloc) {
                    sreloc = elf_section_data(input_section)->sreloc;
                    if (!sreloc || !sreloc->contents) {
                        r = bfd_reloc_notsupported;
                        goto check_relocation_error;
                    }
                    if (relative_reloc_name && htab->params->report_relative_reloc)
                        _bfd_x86_elf_link_report_relative_reloc(
                            info, input_section, h, sym, relative_reloc_name, &outrel);
                    elf_append_rela(output_bfd, sreloc, &outrel);
                }
                if (!relocate)
                    continue;
            }
            break;
        case R_X86_64_TLSGD: case R_X86_64_GOTPC32_TLSDESC: case R_X86_64_CODE_4_GOTPC32_TLSDESC:
        case R_X86_64_TLSDESC_CALL: case R_X86_64_GOTTPOFF: case R_X86_64_CODE_4_GOTTPOFF:
        case R_X86_64_CODE_5_GOTTPOFF: case R_X86_64_CODE_6_GOTTPOFF:
            tls_type = (h == NULL && local_got_offsets) ?
                elf_x86_local_got_tls_type(input_bfd)[r_symndx] :
                (h ? elf_x86_hash_entry(h)->tls_type : GOT_UNKNOWN);
            r_type_tls = r_type;
            if (!elf_x86_64_tls_transition(info, input_bfd, input_section,
                                           contents, symtab_hdr, sym_hashes,
                                           &r_type_tls, tls_type, rel, relend, h, sym, true))
                return false;
            if (r_type_tls == R_X86_64_TPOFF32) {
                bfd_vma roff = rel->r_offset;
                if (roff >= input_section->size) goto corrupt_input;
                BFD_ASSERT(!unresolved_reloc);
                goto tls_reloc_done;
            }
            if (!htab->elf.sgot) abort();
            if (h != NULL) {
                off = h->got.offset;
                offplt = elf_x86_hash_entry(h)->tlsdesc_got;
            } else {
                if (!local_got_offsets) abort();
                off = local_got_offsets[r_symndx];
                offplt = local_tlsdesc_gotents[r_symndx];
            }
            if ((off & 1) != 0)
                off &= ~1;
            else {
                Elf_Internal_Rela outrel;
                int dr_type, indx;
                asection *sreloc;
                if (!htab->elf.srelgot) abort();
                indx = (h && h->dynindx != -1) ? h->dynindx : 0;
                if (GOT_TLS_GDESC_P(tls_type)) {
                    outrel.r_info = htab->r_info(indx, R_X86_64_TLSDESC);
                    BFD_ASSERT(htab->sgotplt_jump_table_size + offplt +
                               2 * GOT_ENTRY_SIZE <= htab->elf.sgotplt->size);
                    outrel.r_offset = htab->elf.sgotplt->output_section->vma
                        + htab->elf.sgotplt->output_offset + offplt
                        + htab->sgotplt_jump_table_size;
                    sreloc = htab->rel_tls_desc;
                    outrel.r_addend = indx == 0
                        ? relocation - _bfd_x86_elf_dtpoff_base(info)
                        : 0;
                    elf_append_rela(output_bfd, sreloc, &outrel);
                }
                sreloc = htab->elf.srelgot;
                outrel.r_offset = htab->elf.sgot->output_section->vma
                                  + htab->elf.sgot->output_offset + off;
                if (GOT_TLS_GD_P(tls_type)) dr_type = R_X86_64_DTPMOD64;
                else if (GOT_TLS_GDESC_P(tls_type)) goto dr_done;
                else dr_type = R_X86_64_TPOFF64;

                bfd_put_64(output_bfd, 0, htab->elf.sgot->contents + off);
                outrel.r_addend = 0;
                if ((dr_type == R_X86_64_TPOFF64
                     || dr_type == R_X86_64_TLSDESC) && indx == 0)
                    outrel.r_addend = relocation - _bfd_x86_elf_dtpoff_base(info);
                outrel.r_info = htab->r_info(indx, dr_type);
                elf_append_rela(output_bfd, sreloc, &outrel);
                if (GOT_TLS_GD_P(tls_type)) {
                    if (indx == 0) {
                        BFD_ASSERT(!unresolved_reloc);
                        bfd_put_64(output_bfd, relocation - _bfd_x86_elf_dtpoff_base(info),
                                   htab->elf.sgot->contents + off + GOT_ENTRY_SIZE);
                    } else {
                        bfd_put_64(output_bfd, 0,
                                   htab->elf.sgot->contents + off + GOT_ENTRY_SIZE);
                        outrel.r_info = htab->r_info(indx, R_X86_64_DTPOFF64);
                        outrel.r_offset += GOT_ENTRY_SIZE;
                        elf_append_rela(output_bfd, sreloc, &outrel);
                    }
                }
dr_done:
                if (h) h->got.offset |= 1;
                else local_got_offsets[r_symndx] |= 1;
            }
            if (off >= (bfd_vma)-2 && !GOT_TLS_GDESC_P(tls_type))
                abort();
            if (r_type_tls == r_type) {
                if (r_type == R_X86_64_GOTPC32_TLSDESC ||
                    r_type == R_X86_64_CODE_4_GOTPC32_TLSDESC ||
                    r_type == R_X86_64_TLSDESC_CALL)
                    relocation = htab->elf.sgotplt->output_section->vma
                        + htab->elf.sgotplt->output_offset + offplt
                        + htab->sgotplt_jump_table_size;
                else
                    relocation = htab->elf.sgot->output_section->vma
                        + htab->elf.sgot->output_offset + off;
                unresolved_reloc = false;
            }
            break;
tls_reloc_done:
            break;
        case R_X86_64_TLSLD:
            if (!elf_x86_64_tls_transition(info, input_bfd, input_section, contents,
                symtab_hdr, sym_hashes, &r_type, GOT_UNKNOWN, rel,
                relend, h, sym, true))
                return false;
            if (r_type != R_X86_64_TLSLD) {
                BFD_ASSERT(r_type == R_X86_64_TPOFF32);
                goto tlsld_done;
            }
            if (!htab->elf.sgot) abort();
            off = htab->tls_ld_or_ldm_got.offset;
            if (off & 1)
                off &= ~1;
            else {
                Elf_Internal_Rela outrel;
                if (!htab->elf.srelgot) abort();
                outrel.r_offset = htab->elf.sgot->output_section->vma +
                                  htab->elf.sgot->output_offset + off;
                bfd_put_64(output_bfd, 0, htab->elf.sgot->contents + off);
                bfd_put_64(output_bfd, 0, htab->elf.sgot->contents + off + GOT_ENTRY_SIZE);
                outrel.r_info = htab->r_info(0, R_X86_64_DTPMOD64);
                outrel.r_addend = 0;
                elf_append_rela(output_bfd, htab->elf.srelgot, &outrel);
                htab->tls_ld_or_ldm_got.offset |= 1;
            }
            relocation = htab->elf.sgot->output_section->vma +
                         htab->elf.sgot->output_offset + off;
            unresolved_reloc = false;
            break;
tlsld_done:
            break;
        case R_X86_64_DTPOFF32:
            if (!bfd_link_executable(info) || (input_section->flags & SEC_CODE) == 0)
                relocation -= _bfd_x86_elf_dtpoff_base(info);
            else
                relocation = elf_x86_64_tpoff(info, relocation);
            break;
        case R_X86_64_TPOFF32: case R_X86_64_TPOFF64:
            BFD_ASSERT(bfd_link_executable(info));
            relocation = elf_x86_64_tpoff(info, relocation);
            break;
        case R_X86_64_DTPOFF64:
            BFD_ASSERT((input_section->flags & SEC_CODE) == 0);
            relocation -= _bfd_x86_elf_dtpoff_base(info);
            break;
        }

        if (unresolved_reloc &&
            !((input_section->flags & SEC_DEBUGGING) && h->def_dynamic) &&
            _bfd_elf_section_offset(output_bfd, info, input_section, rel->r_offset) != (bfd_vma)-1)
        {
            switch (r_type) {
            case R_X86_64_32S:
                sec = h->root.u.def.section;
                if ((info->nocopyreloc || eh->def_protected) &&
                    !(h->root.u.def.section->flags & SEC_CODE))
                    return elf_x86_64_need_pic(info, input_bfd, input_section,
                                              h, NULL, NULL, howto);
            default:
                _bfd_error_handler(
                    _("%pB(%pA+%#" PRIx64 "): unresolvable %s relocation against symbol `%s'"),
                    input_bfd, input_section, (uint64_t)rel->r_offset,
                    howto->name, h->root.root.string);
                return false;
            }
        }

do_relocation:
        r = _bfd_final_link_relocate(howto, input_bfd, input_section, contents, rel->r_offset, relocation, rel->r_addend);

check_relocation_error:
        if (r != bfd_reloc_ok) {
            const char *name;
            if (h)
                name = h->root.root.string;
            else {
                name = bfd_elf_string_from_elf_section(input_bfd, symtab_hdr->sh_link, sym->st_name);
                if (!name) return false;
                if (!*name) name = bfd_section_name(sec);
            }
            if (r == bfd_reloc_overflow) {
                if (converted_reloc) {
                    info->callbacks->einfo("%X%H:", input_bfd, input_section, rel->r_offset);
                    info->callbacks->einfo(
                        _(" failed to convert GOTPCREL relocation against "
                          "'%s'; relink with --no-relax\n"), name);
                    status = false;
                    continue;
                }
                (*info->callbacks->reloc_overflow)(
                    info, h ? &h->root : NULL, name, howto->name, (bfd_vma)0, input_bfd, input_section, rel->r_offset);
            } else {
                _bfd_error_handler(
                    _("%pB(%pA+%#" PRIx64 "): reloc against `%s': error %d"),
                    input_bfd, input_section,
                    (uint64_t)rel->r_offset, name, (int)r);
                return false;
            }
        }
        if (wrel != rel) *wrel = *rel;
    }

    if (wrel != rel) {
        Elf_Internal_Shdr *rel_hdr;
        size_t deleted = rel - wrel;
        rel_hdr = _bfd_elf_single_rel_hdr(input_section->output_section);
        rel_hdr->sh_size -= rel_hdr->sh_entsize * deleted;
        rel_hdr = _bfd_elf_single_rel_hdr(input_section);
        rel_hdr->sh_size -= rel_hdr->sh_entsize * deleted;
        input_section->reloc_count -= deleted;
    }

    return status;
}


/* Finish up dynamic symbol handling.  We set the contents of various
   dynamic sections here.  */

static bool
elf_x86_64_finish_dynamic_symbol(bfd *output_bfd,
				 struct bfd_link_info *info,
				 struct elf_link_hash_entry *h,
				 Elf_Internal_Sym *sym)
{
  struct elf_x86_link_hash_table *htab = elf_x86_hash_table(info, X86_64_ELF_DATA);
  bool use_plt_second = htab->elf.splt != NULL && htab->plt_second != NULL;
  struct elf_x86_link_hash_entry *eh = (struct elf_x86_link_hash_entry *)h;
  bool local_undefweak = UNDEFINED_WEAK_RESOLVED_TO_ZERO(info, eh);

  if (eh->no_finish_dynamic_symbol)
    abort();

  if (h->plt.offset != (bfd_vma)-1)
    {
      bfd_vma plt_index, got_offset, plt_offset;
      Elf_Internal_Rela rela;
      bfd_byte *loc;
      asection *plt, *gotplt, *relplt, *resolved_plt;
      const struct elf_backend_data *bed;
      bfd_vma plt_got_pcrel_offset;

      if (htab->elf.splt != NULL)
	{
	  plt = htab->elf.splt;
	  gotplt = htab->elf.sgotplt;
	  relplt = htab->elf.srelplt;
	}
      else
	{
	  plt = htab->elf.iplt;
	  gotplt = htab->elf.igotplt;
	  relplt = htab->elf.irelplt;
	}

      VERIFY_PLT_ENTRY(info, h, plt, gotplt, relplt, local_undefweak);

      if (plt == htab->elf.splt)
	{
	  got_offset = (h->plt.offset / htab->plt.plt_entry_size - htab->plt.has_plt0);
	  got_offset = (got_offset + 3) * GOT_ENTRY_SIZE;
	}
      else
	{
	  got_offset = (h->plt.offset / htab->plt.plt_entry_size) * GOT_ENTRY_SIZE;
	}

      memcpy(plt->contents + h->plt.offset, htab->plt.plt_entry, htab->plt.plt_entry_size);

      if (use_plt_second)
	{
	  memcpy(htab->plt_second->contents + eh->plt_second.offset,
		 htab->non_lazy_plt->plt_entry,
		 htab->non_lazy_plt->plt_entry_size);
	  resolved_plt = htab->plt_second;
	  plt_offset = eh->plt_second.offset;
	}
      else
	{
	  resolved_plt = plt;
	  plt_offset = h->plt.offset;
	}

      plt_got_pcrel_offset =
	(gotplt->output_section->vma + gotplt->output_offset + got_offset
	 - resolved_plt->output_section->vma
	 - resolved_plt->output_offset - plt_offset - htab->plt.plt_got_insn_size);

      if ((plt_got_pcrel_offset + 0x80000000) > 0xffffffff)
	info->callbacks->fatal(_("%pB: PC-relative offset overflow in PLT entry for `%s'\n"), output_bfd, h->root.root.string);

      bfd_put_32(output_bfd, plt_got_pcrel_offset,
		 (resolved_plt->contents + plt_offset + htab->plt.plt_got_offset));

      if (!local_undefweak)
	{
	  if (htab->plt.has_plt0)
	    bfd_put_64(output_bfd,
		       (plt->output_section->vma + plt->output_offset
			+ h->plt.offset + htab->lazy_plt->plt_lazy_offset),
		       gotplt->contents + got_offset);

	  rela.r_offset = (gotplt->output_section->vma + gotplt->output_offset + got_offset);
	  if (PLT_LOCAL_IFUNC_P(info, h))
	    {
	      if (h->root.u.def.section == NULL)
		return false;

	      info->callbacks->minfo(_("Local IFUNC function `%s' in %pB\n"),
				     h->root.root.string,
				     h->root.u.def.section->owner);

	      rela.r_info = htab->r_info(0, R_X86_64_IRELATIVE);
	      rela.r_addend = (h->root.u.def.value
			       + h->root.u.def.section->output_section->vma
			       + h->root.u.def.section->output_offset);

	      if (htab->params->report_relative_reloc)
		_bfd_x86_elf_link_report_relative_reloc(info, relplt, h, sym, "R_X86_64_IRELATIVE", &rela);

	      plt_index = htab->next_irelative_index--;
	    }
	  else
	    {
	      rela.r_info = htab->r_info(h->dynindx, R_X86_64_JUMP_SLOT);
	      if (htab->params->mark_plt)
		rela.r_addend = (resolved_plt->output_section->vma + plt_offset + htab->plt.plt_indirect_branch_offset);
	      else
		rela.r_addend = 0;
	      plt_index = htab->next_jump_slot_index++;
	    }

	  if (plt == htab->elf.splt && htab->plt.has_plt0)
	    {
	      bfd_vma plt0_offset = h->plt.offset + htab->lazy_plt->plt_plt_insn_end;

	      bfd_put_32(output_bfd, plt_index,
			 (plt->contents + h->plt.offset + htab->lazy_plt->plt_reloc_offset));

	      if (plt0_offset > 0x80000000)
		info->callbacks->fatal(_("%pB: branch displacement overflow in PLT entry for `%s'\n"),
				      output_bfd, h->root.root.string);
	      bfd_put_32(output_bfd, -plt0_offset,
			 (plt->contents + h->plt.offset + htab->lazy_plt->plt_plt_offset));
	    }

	  bed = get_elf_backend_data(output_bfd);
	  loc = relplt->contents + plt_index * bed->s->sizeof_rela;
	  bed->s->swap_reloca_out(output_bfd, &rela, loc);
	}
    }
  else if (eh->plt_got.offset != (bfd_vma)-1)
    {
      bfd_vma got_offset = h->got.offset, plt_offset;
      asection *plt = htab->plt_got, *got = htab->elf.sgot;
      bool got_after_plt;
      int32_t got_pcrel_offset;

      if (got_offset == (bfd_vma)-1 ||
          (h->type == STT_GNU_IFUNC && h->def_regular) ||
          plt == NULL || got == NULL)
	abort();

      plt_offset = eh->plt_got.offset;
      memcpy(plt->contents + plt_offset, htab->non_lazy_plt->plt_entry, htab->non_lazy_plt->plt_entry_size);

      got_pcrel_offset =
	(got->output_section->vma + got->output_offset + got_offset
	 - plt->output_section->vma - plt->output_offset
	 - plt_offset - htab->non_lazy_plt->plt_got_insn_size);

      got_after_plt = got->output_section->vma > plt->output_section->vma;
      if ((got_after_plt && got_pcrel_offset < 0) || (!got_after_plt && got_pcrel_offset > 0))
	info->callbacks->fatal(_("%pB: PC-relative offset overflow in GOT PLT entry for `%s'\n"),
			      output_bfd, h->root.root.string);

      bfd_put_32(output_bfd, got_pcrel_offset,
		 (plt->contents + plt_offset + htab->non_lazy_plt->plt_got_offset));
    }

  if (!local_undefweak && !h->def_regular
      && (h->plt.offset != (bfd_vma)-1 || eh->plt_got.offset != (bfd_vma)-1))
    {
      sym->st_shndx = SHN_UNDEF;
      if (!h->pointer_equality_needed)
	sym->st_value = 0;
    }

  _bfd_x86_elf_link_fixup_ifunc_symbol(info, htab, h, sym);

  if (h->got.offset != (bfd_vma)-1
      && !GOT_TLS_GD_ANY_P(elf_x86_hash_entry(h)->tls_type)
      && elf_x86_hash_entry(h)->tls_type != GOT_TLS_IE
      && !local_undefweak)
    {
      Elf_Internal_Rela rela;
      asection *relgot = htab->elf.srelgot;
      const char *relative_reloc_name = NULL;
      bool generate_dynamic_reloc = true;

      if (htab->elf.sgot == NULL || htab->elf.srelgot == NULL)
	abort();

      rela.r_offset = (htab->elf.sgot->output_section->vma +
			htab->elf.sgot->output_offset +
			(h->got.offset & ~(bfd_vma)1));

      if (h->def_regular && h->type == STT_GNU_IFUNC)
	{
	  if (h->plt.offset == (bfd_vma)-1)
	    {
	      if (htab->elf.splt == NULL)
		relgot = htab->elf.irelplt;
	      if (SYMBOL_REFERENCES_LOCAL_P(info, h))
		{
		  if (h->root.u.def.section == NULL)
		    return false;

		  info->callbacks->minfo(_("Local IFUNC function `%s' in %pB\n"),
					 h->root.root.string,
					 h->root.u.def.section->owner);

		  rela.r_info = htab->r_info(0, R_X86_64_IRELATIVE);
		  rela.r_addend = (h->root.u.def.value +
				   h->root.u.def.section->output_section->vma +
				   h->root.u.def.section->output_offset);
		  relative_reloc_name = "R_X86_64_IRELATIVE";
		}
	      else
		goto do_glob_dat;
	    }
	  else if (bfd_link_pic(info))
	    goto do_glob_dat;
	  else
	    {
	      asection *plt;
	      bfd_vma plt_offset;
	      if (!h->pointer_equality_needed)
		abort();

	      if (htab->plt_second != NULL)
		{
		  plt = htab->plt_second;
		  plt_offset = eh->plt_second.offset;
		}
	      else
		{
		  plt = htab->elf.splt ? htab->elf.splt : htab->elf.iplt;
		  plt_offset = h->plt.offset;
		}
	      bfd_put_64(output_bfd,
			 plt->output_section->vma + plt->output_offset + plt_offset,
			 htab->elf.sgot->contents + h->got.offset);
	      return true;
	    }
	}
      else if (bfd_link_pic(info) && SYMBOL_REFERENCES_LOCAL_P(info, h))
	{
	  if (!SYMBOL_DEFINED_NON_SHARED_P(h))
	    return false;
	  BFD_ASSERT((h->got.offset & 1) != 0);
	  if (info->enable_dt_relr)
	    generate_dynamic_reloc = false;
	  else
	    {
	      rela.r_info = htab->r_info(0, R_X86_64_RELATIVE);
	      rela.r_addend = (h->root.u.def.value +
			       h->root.u.def.section->output_section->vma +
			       h->root.u.def.section->output_offset);
	      relative_reloc_name = "R_X86_64_RELATIVE";
	    }
	}
      else
	{
	  BFD_ASSERT((h->got.offset & 1) == 0);
	do_glob_dat:
	  bfd_put_64(output_bfd, (bfd_vma)0, htab->elf.sgot->contents + h->got.offset);
	  rela.r_info = htab->r_info(h->dynindx, R_X86_64_GLOB_DAT);
	  rela.r_addend = 0;
	}

      if (generate_dynamic_reloc)
	{
	  if (relgot == NULL || relgot->size == 0)
	    {
	      info->callbacks->fatal(_("%pB: Unable to generate dynamic relocs because a suitable section does not exist\n"),
				    output_bfd);
	      return false;
	    }

	  if (relative_reloc_name != NULL && htab->params->report_relative_reloc)
	    _bfd_x86_elf_link_report_relative_reloc(info, relgot, h, sym, relative_reloc_name, &rela);

	  elf_append_rela(output_bfd, relgot, &rela);
	}
    }

  if (h->needs_copy)
    {
      Elf_Internal_Rela rela;
      asection *s;

      VERIFY_COPY_RELOC(h, htab);

      rela.r_offset = (h->root.u.def.value +
		       h->root.u.def.section->output_section->vma +
		       h->root.u.def.section->output_offset);
      rela.r_info = htab->r_info(h->dynindx, R_X86_64_COPY);
      rela.r_addend = 0;
      s = (h->root.u.def.section == htab->elf.sdynrelro)
	    ? htab->elf.sreldynrelro
	    : htab->elf.srelbss;
      elf_append_rela(output_bfd, s, &rela);
    }

  return true;
}


/* Finish up local dynamic symbol handling.  We set the contents of
   various dynamic sections here.  */

static int elf_x86_64_finish_local_dynamic_symbol(void **slot, void *inf) {
  if (!slot || !*slot || !inf) {
    return 0;
  }

  struct elf_link_hash_entry *h = (struct elf_link_hash_entry *)*slot;
  struct bfd_link_info *info = (struct bfd_link_info *)inf;

  if (!info->output_bfd) {
    return 0;
  }

  return elf_x86_64_finish_dynamic_symbol(info->output_bfd, info, h, NULL);
}

/* Finish up undefined weak symbol handling in PIE.  Fill its PLT entry
   here since undefined weak symbol may not be dynamic and may not be
   called for elf_x86_64_finish_dynamic_symbol.  */

static bool elf_x86_64_pie_finish_undefweak_symbol(struct bfd_hash_entry *bh, void *inf) {
    struct elf_link_hash_entry *h = (struct elf_link_hash_entry *)bh;
    struct bfd_link_info *info = (struct bfd_link_info *)inf;

    if (h == NULL || info == NULL)
        return false;

    if (h->root.type == bfd_link_hash_undefweak && h->dynindx == -1)
        return elf_x86_64_finish_dynamic_symbol(info->output_bfd, info, h, NULL);

    return true;
}

/* Used to decide how to sort relocs in an optimal manner for the
   dynamic linker, before writing them out.  */

static enum elf_reloc_type_class
elf_x86_64_reloc_type_class(const struct bfd_link_info *info,
                            const asection *rel_sec ATTRIBUTE_UNUSED,
                            const Elf_Internal_Rela *rela)
{
    bfd *abfd = info->output_bfd;
    const struct elf_backend_data *bed = get_elf_backend_data(abfd);
    struct elf_x86_link_hash_table *htab = elf_x86_hash_table(info, X86_64_ELF_DATA);

    if (htab && htab->elf.dynsym && htab->elf.dynsym->contents) {
        unsigned long r_symndx = htab->r_sym(rela->r_info);
        if (r_symndx != STN_UNDEF) {
            Elf_Internal_Sym sym;
            const void *sym_addr = (const char *)htab->elf.dynsym->contents + r_symndx * bed->s->sizeof_sym;
            if (!bed->s->swap_symbol_in(abfd, sym_addr, 0, &sym)) {
                return reloc_class_normal;
            }
            if (ELF_ST_TYPE(sym.st_info) == STT_GNU_IFUNC) {
                return reloc_class_ifunc;
            }
        }
    }

    switch ((int)ELF32_R_TYPE(rela->r_info)) {
    case R_X86_64_IRELATIVE:
        return reloc_class_ifunc;
    case R_X86_64_RELATIVE:
    case R_X86_64_RELATIVE64:
        return reloc_class_relative;
    case R_X86_64_JUMP_SLOT:
        return reloc_class_plt;
    case R_X86_64_COPY:
        return reloc_class_copy;
    default:
        return reloc_class_normal;
    }
}

/* Finish up the dynamic sections.  */

static bool
elf_x86_64_finish_dynamic_sections(bfd *output_bfd, struct bfd_link_info *info)
{
    struct elf_x86_link_hash_table *htab = _bfd_x86_elf_finish_dynamic_sections(output_bfd, info);
    if (htab == NULL)
        return false;

    if (!htab->elf.dynamic_sections_created)
        return true;

    if (htab->elf.splt && htab->elf.splt->size > 0) {
        if (bfd_is_abs_section(htab->elf.splt->output_section)) {
            if (info && info->callbacks && info->callbacks->fatal) {
                info->callbacks->fatal(_("%P: discarded output section: `%pA'\n"), htab->elf.splt);
            }
            return false;
        }

        elf_section_data(htab->elf.splt->output_section)->this_hdr.sh_entsize = htab->plt.plt_entry_size;

        if (htab->plt.has_plt0 && htab->elf.splt->contents && htab->lazy_plt) {
            memcpy(htab->elf.splt->contents, htab->lazy_plt->plt0_entry, htab->lazy_plt->plt0_entry_size);

            if (htab->elf.sgotplt && htab->elf.splt->output_section && htab->elf.sgotplt->output_section) {
                bfd_vma plt0_got1_offset = htab->elf.sgotplt->output_section->vma + htab->elf.sgotplt->output_offset + 8
                    - htab->elf.splt->output_section->vma - htab->elf.splt->output_offset - 6;
                bfd_put_32(output_bfd, plt0_got1_offset, htab->elf.splt->contents + htab->lazy_plt->plt0_got1_offset);

                bfd_vma plt0_got2_offset = htab->elf.sgotplt->output_section->vma + htab->elf.sgotplt->output_offset + 16
                    - htab->elf.splt->output_section->vma - htab->elf.splt->output_offset - htab->lazy_plt->plt0_got2_insn_end;
                bfd_put_32(output_bfd, plt0_got2_offset, htab->elf.splt->contents + htab->lazy_plt->plt0_got2_offset);
            }
        }

        if (htab->elf.tlsdesc_plt && htab->elf.sgot && htab->elf.sgot->contents && htab->lazy_plt) {
            bfd_put_64(output_bfd, (bfd_vma)0, htab->elf.sgot->contents + htab->elf.tlsdesc_got);

            if (htab->elf.splt->contents && htab->lazy_plt->plt_tlsdesc_entry) {
                memcpy(htab->elf.splt->contents + htab->elf.tlsdesc_plt, htab->lazy_plt->plt_tlsdesc_entry, htab->lazy_plt->plt_tlsdesc_entry_size);

                if (htab->elf.sgotplt && htab->elf.sgotplt->output_section && htab->elf.splt->output_section) {
                    bfd_vma tlsdesc_got1_offset = htab->elf.sgotplt->output_section->vma + htab->elf.sgotplt->output_offset + 8
                        - htab->elf.splt->output_section->vma - htab->elf.splt->output_offset - htab->elf.tlsdesc_plt
                        - htab->lazy_plt->plt_tlsdesc_got1_insn_end;
                    bfd_put_32(output_bfd, tlsdesc_got1_offset, htab->elf.splt->contents + htab->elf.tlsdesc_plt + htab->lazy_plt->plt_tlsdesc_got1_offset);
                }

                if (htab->elf.sgot && htab->elf.sgot->output_section && htab->elf.splt->output_section) {
                    bfd_vma tlsdesc_got2_offset = htab->elf.sgot->output_section->vma + htab->elf.sgot->output_offset + htab->elf.tlsdesc_got
                        - htab->elf.splt->output_section->vma - htab->elf.splt->output_offset - htab->elf.tlsdesc_plt
                        - htab->lazy_plt->plt_tlsdesc_got2_insn_end;
                    bfd_put_32(output_bfd, tlsdesc_got2_offset, htab->elf.splt->contents + htab->elf.tlsdesc_plt + htab->lazy_plt->plt_tlsdesc_got2_offset);
                }
            }
        }
    }

    if (bfd_link_pie(info) && info && info->hash)
        bfd_hash_traverse(&info->hash->table, elf_x86_64_pie_finish_undefweak_symbol, info);

    return true;
}

/* Fill PLT/GOT entries and allocate dynamic relocations for local
   STT_GNU_IFUNC symbols, which aren't in the ELF linker hash table.
   It has to be done before elf_link_sort_relocs is called so that
   dynamic relocations are properly sorted.  */

static bool elf_x86_64_output_arch_local_syms(
    bfd *output_bfd ATTRIBUTE_UNUSED,
    struct bfd_link_info *info,
    void *flaginfo ATTRIBUTE_UNUSED,
    int (*func)(void *, const char *, Elf_Internal_Sym *, asection *, struct elf_link_hash_entry *) ATTRIBUTE_UNUSED)
{
    struct elf_x86_link_hash_table *htab = elf_x86_hash_table(info, X86_64_ELF_DATA);
    if (!htab)
        return false;

    htab_traverse(htab->loc_hash_table, elf_x86_64_finish_local_dynamic_symbol, info);

    return true;
}

/* Similar to _bfd_elf_get_synthetic_symtab.  Support PLTs with all
   dynamic relocations.   */

static long
elf_x86_64_get_synthetic_symtab(bfd *abfd,
                                long symcount ATTRIBUTE_UNUSED,
                                asymbol **syms ATTRIBUTE_UNUSED,
                                long dynsymcount,
                                asymbol **dynsyms,
                                asymbol **ret)
{
    long count = 0;
    bfd_byte *plt_contents = NULL;
    long relsize;
    const struct elf_x86_lazy_plt_layout *lazy_plt = &elf_x86_64_lazy_plt;
    const struct elf_x86_non_lazy_plt_layout *non_lazy_plt = &elf_x86_64_non_lazy_plt;
    const struct elf_x86_lazy_plt_layout *lazy_bnd_plt = NULL;
    const struct elf_x86_non_lazy_plt_layout *non_lazy_bnd_plt = NULL;
    const struct elf_x86_lazy_plt_layout *lazy_bnd_ibt_plt = NULL;
    const struct elf_x86_non_lazy_plt_layout *non_lazy_bnd_ibt_plt = NULL;
    const struct elf_x86_lazy_plt_layout *lazy_ibt_plt = &elf_x86_64_lazy_ibt_plt;
    const struct elf_x86_non_lazy_plt_layout *non_lazy_ibt_plt = &elf_x86_64_non_lazy_ibt_plt;
    asection *plt = NULL;
    enum elf_x86_plt_type plt_type;

    struct elf_x86_plt plts[] = {
        { ".plt", NULL, NULL, plt_unknown, 0, 0, 0, 0 },
        { ".plt.got", NULL, NULL, plt_non_lazy, 0, 0, 0, 0 },
        { ".plt.sec", NULL, NULL, plt_second, 0, 0, 0, 0 },
        { ".plt.bnd", NULL, NULL, plt_second, 0, 0, 0, 0 },
        { NULL, NULL, NULL, plt_non_lazy, 0, 0, 0, 0 }
    };

    *ret = NULL;

    if ((abfd->flags & (DYNAMIC | EXEC_P)) == 0 || dynsymcount <= 0)
        return 0;

    relsize = bfd_get_dynamic_reloc_upper_bound(abfd);
    if (relsize <= 0)
        return -1;

    if (ABI_64_P(abfd)) {
        lazy_bnd_ibt_plt = &elf_x86_64_lazy_bnd_ibt_plt;
        non_lazy_bnd_ibt_plt = &elf_x86_64_non_lazy_bnd_ibt_plt;
        lazy_bnd_plt = &elf_x86_64_lazy_bnd_plt;
        non_lazy_bnd_plt = &elf_x86_64_non_lazy_bnd_plt;
    }

    for (int j = 0; plts[j].name != NULL; j++) {
        long i, n;
        plt = bfd_get_section_by_name(abfd, plts[j].name);
        if (!plt || plt->size == 0 || (plt->flags & SEC_HAS_CONTENTS) == 0)
            continue;

        if (!_bfd_elf_mmap_section_contents(abfd, plt, &plt_contents))
            break;

        plt_type = plt_unknown;

        if (plts[j].type == plt_unknown &&
            plt->size >= (lazy_plt->plt_entry_size + lazy_plt->plt_entry_size)) 
        {
            if (memcmp(plt_contents, lazy_plt->plt0_entry, lazy_plt->plt0_got1_offset) == 0 &&
                memcmp(plt_contents + 6, lazy_plt->plt0_entry + 6, 2) == 0) 
            {
                if (memcmp(plt_contents + lazy_ibt_plt->plt_entry_size,
                           lazy_ibt_plt->plt_entry,
                           lazy_ibt_plt->plt_reloc_offset) == 0)
                {
                    plt_type = plt_lazy | plt_second;
                    lazy_plt = lazy_ibt_plt;
                }
                else
                    plt_type = plt_lazy;
            }
            else if (lazy_bnd_plt &&
                    memcmp(plt_contents, lazy_bnd_plt->plt0_entry, lazy_bnd_plt->plt0_got1_offset) == 0 &&
                    memcmp(plt_contents + 6, lazy_bnd_plt->plt0_entry + 6, 3) == 0)
            {
                plt_type = plt_lazy | plt_second;
                if (memcmp(plt_contents + lazy_bnd_ibt_plt->plt_entry_size,
                           lazy_bnd_ibt_plt->plt_entry,
                           lazy_bnd_ibt_plt->plt_reloc_offset) == 0)
                    lazy_plt = lazy_bnd_ibt_plt;
                else
                    lazy_plt = lazy_bnd_plt;
            }
        }

        if (non_lazy_plt &&
            (plt_type == plt_unknown || plt_type == plt_non_lazy) &&
            plt->size >= non_lazy_plt->plt_entry_size)
        {
            if (memcmp(plt_contents, non_lazy_plt->plt_entry, non_lazy_plt->plt_got_offset) == 0)
                plt_type = plt_non_lazy;
        }

        if (plt_type == plt_unknown || plt_type == plt_second) {
            if (plt->size >= non_lazy_ibt_plt->plt_entry_size &&
                memcmp(plt_contents, non_lazy_ibt_plt->plt_entry, non_lazy_ibt_plt->plt_got_offset) == 0)
            {
                plt_type = plt_second;
                non_lazy_plt = non_lazy_ibt_plt;
            }
            else if (non_lazy_bnd_plt) {
                if (plt->size >= non_lazy_bnd_plt->plt_entry_size &&
                    memcmp(plt_contents, non_lazy_bnd_plt->plt_entry, non_lazy_bnd_plt->plt_got_offset) == 0)
                {
                    plt_type = plt_second;
                    non_lazy_plt = non_lazy_bnd_plt;
                }
                else if (plt->size >= non_lazy_bnd_ibt_plt->plt_entry_size &&
                         memcmp(plt_contents, non_lazy_bnd_ibt_plt->plt_entry, non_lazy_bnd_ibt_plt->plt_got_offset) == 0)
                {
                    plt_type = plt_second;
                    non_lazy_plt = non_lazy_bnd_ibt_plt;
                }
            }
        }

        if (plt_type == plt_unknown) {
            _bfd_elf_munmap_section_contents(plt, plt_contents);
            continue;
        }

        plts[j].sec = plt;
        plts[j].type = plt_type;

        if (plt_type & plt_lazy) {
            plts[j].plt_got_offset = lazy_plt->plt_got_offset;
            plts[j].plt_got_insn_size = lazy_plt->plt_got_insn_size;
            plts[j].plt_entry_size = lazy_plt->plt_entry_size;
            i = 1;
        } else {
            plts[j].plt_got_offset = non_lazy_plt->plt_got_offset;
            plts[j].plt_got_insn_size = non_lazy_plt->plt_got_insn_size;
            plts[j].plt_entry_size = non_lazy_plt->plt_entry_size;
            i = 0;
        }

        if (plt_type == (plt_lazy | plt_second)) {
            plts[j].count = 0;
        } else {
            n = plt->size / plts[j].plt_entry_size;
            plts[j].count = n;
            count += n - i;
        }

        plts[j].contents = plt_contents;
    }

    return _bfd_x86_elf_get_synthetic_symtab(abfd, count, relsize, (bfd_vma)0, plts, dynsyms, ret);
}

/* Handle an x86-64 specific section when reading an object file.  This
   is called when elfcode.h finds a section with an unknown type.  */

static bool elf_x86_64_section_from_shdr(bfd *abfd, Elf_Internal_Shdr *hdr, const char *name, int shindex) {
  if (hdr == NULL || abfd == NULL || name == NULL)
    return false;
  if (hdr->sh_type != SHT_X86_64_UNWIND)
    return false;
  return _bfd_elf_make_section_from_shdr(abfd, hdr, name, shindex) ? true : false;
}

/* Hook called by the linker routine which adds symbols from an object
   file.  We use it to put SHN_X86_64_LCOMMON items in .lbss, instead
   of .bss.  */

static bool elf_x86_64_add_symbol_hook(bfd *abfd,
                                       struct bfd_link_info *info ATTRIBUTE_UNUSED,
                                       Elf_Internal_Sym *sym,
                                       const char **namep ATTRIBUTE_UNUSED,
                                       flagword *flagsp ATTRIBUTE_UNUSED,
                                       asection **secp,
                                       bfd_vma *valp)
{
    if (sym == NULL || secp == NULL || valp == NULL || abfd == NULL)
        return false;

    if (sym->st_shndx == SHN_X86_64_LCOMMON)
    {
        asection *lcomm = bfd_get_section_by_name(abfd, "LARGE_COMMON");
        if (lcomm == NULL)
        {
            lcomm = bfd_make_section_with_flags(abfd, "LARGE_COMMON",
                                                SEC_ALLOC | SEC_IS_COMMON | SEC_LINKER_CREATED);
            if (lcomm == NULL)
                return false;
            elf_section_flags(lcomm) |= SHF_X86_64_LARGE;
        }
        *secp = lcomm;
        *valp = sym->st_size;
    }
    return true;
}


/* Given a BFD section, try to locate the corresponding ELF section
   index.  */

static bool elf_x86_64_elf_section_from_bfd_section(bfd *abfd, asection *sec, int *index_return) {
    if (sec == NULL || index_return == NULL)
        return false;
    if (sec == &_bfd_elf_large_com_section) {
        *index_return = SHN_X86_64_LCOMMON;
        return true;
    }
    return false;
}

/* Process a symbol.  */

static void elf_x86_64_symbol_processing(bfd *abfd ATTRIBUTE_UNUSED, asymbol *asym) {
    elf_symbol_type *elfsym = (elf_symbol_type *)asym;
    if (elfsym->internal_elf_sym.st_shndx == SHN_X86_64_LCOMMON) {
        asym->section = &_bfd_elf_large_com_section;
        asym->value = elfsym->internal_elf_sym.st_size;
        asym->flags &= ~BSF_GLOBAL;
    }
}

static bool elf_x86_64_common_definition(const Elf_Internal_Sym *sym) {
    if (sym == NULL) {
        return false;
    }
    return sym->st_shndx == SHN_COMMON || sym->st_shndx == SHN_X86_64_LCOMMON;
}

static unsigned int elf_x86_64_common_section_index(asection *sec) {
    return (elf_section_flags(sec) & SHF_X86_64_LARGE) ? SHN_X86_64_LCOMMON : SHN_COMMON;
}

static asection *
elf_x86_64_common_section(asection *sec)
{
  return (elf_section_flags(sec) & SHF_X86_64_LARGE)
           ? &_bfd_elf_large_com_section
           : bfd_com_section_ptr;
}

static bool elf_x86_64_merge_symbol(struct elf_link_hash_entry *h,
                                    const Elf_Internal_Sym *sym,
                                    asection **psec,
                                    bool newdef,
                                    bool olddef,
                                    bfd *oldbfd,
                                    const asection *oldsec)
{
    if (!olddef &&
        h->root.type == bfd_link_hash_common &&
        !newdef &&
        bfd_is_com_section(*psec) &&
        oldsec != *psec)
    {
        unsigned int oldsec_flags = elf_section_flags(oldsec);
        if (sym->st_shndx == SHN_COMMON && (oldsec_flags & SHF_X86_64_LARGE))
        {
            asection *common_section = bfd_make_section_old_way(oldbfd, "COMMON");
            if (common_section)
            {
                common_section->flags = SEC_ALLOC;
                if (h->root.u.c.p)
                    h->root.u.c.p->section = common_section;
            }
        }
        else if (sym->st_shndx == SHN_X86_64_LCOMMON && !(oldsec_flags & SHF_X86_64_LARGE))
        {
            *psec = bfd_com_section_ptr;
        }
    }
    return true;
}

static bool
elf_x86_64_section_flags(const Elf_Internal_Shdr *hdr)
{
  if (!hdr || !hdr->bfd_section)
    return false;

  if (hdr->sh_flags & SHF_X86_64_LARGE)
    hdr->bfd_section->flags |= SEC_ELF_LARGE;

  return true;
}

static bool elf_x86_64_fake_sections(bfd *abfd, Elf_Internal_Shdr *hdr, asection *sec) {
    (void)abfd;
    if ((sec->flags & SEC_ELF_LARGE) != 0) {
        hdr->sh_flags |= SHF_X86_64_LARGE;
    }
    return true;
}

static bool elf_x86_64_copy_private_section_data(bfd *ibfd, asection *isec,
                                                bfd *obfd, asection *osec,
                                                struct bfd_link_info *link_info)
{
    if (!_bfd_elf_copy_private_section_data(ibfd, isec, obfd, osec, link_info))
        return false;

    if (link_info == NULL && ibfd != obfd) {
        elf_section_flags(osec) &= ~SHF_X86_64_LARGE;
    }

    return true;
}

static int elf_x86_64_additional_program_headers(bfd *abfd, struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  int count = 0;

  if (abfd == NULL)
    return 0;

  asection *s_lrodata = bfd_get_section_by_name(abfd, ".lrodata");
  if (s_lrodata != NULL && (s_lrodata->flags & SEC_LOAD))
    count++;

  asection *s_ldata = bfd_get_section_by_name(abfd, ".ldata");
  if (s_ldata != NULL && (s_ldata->flags & SEC_LOAD))
    count++;

  return count;
}

/* Return TRUE iff relocations for INPUT are compatible with OUTPUT. */

static bool elf_x86_64_relocs_compatible(const bfd_target *input, const bfd_target *output)
{
    const struct elf_backend_data *input_data = xvec_get_elf_backend_data(input);
    const struct elf_backend_data *output_data = xvec_get_elf_backend_data(output);

    if (!input_data || !output_data || !input_data->s || !output_data->s)
        return false;

    if (input_data->s->elfclass != output_data->s->elfclass)
        return false;

    return _bfd_elf_relocs_compatible(input, output);
}

/* Set up x86-64 GNU properties.  Return the first relocatable ELF input
   with GNU properties if found.  Otherwise, return NULL.  */

static bfd *
elf_x86_64_link_setup_gnu_properties(struct bfd_link_info *info)
{
    struct elf_x86_init_table init_table = {0};
    const struct elf_backend_data *bed;
    struct elf_x86_link_hash_table *htab;
    int r_conv_bit = (int)R_X86_64_converted_reloc_bit;

    if ((int)R_X86_64_standard >= r_conv_bit ||
        (int)R_X86_64_max <= r_conv_bit ||
        (((int)R_X86_64_GNU_VTINHERIT | r_conv_bit) != (int)R_X86_64_GNU_VTINHERIT) ||
        (((int)R_X86_64_GNU_VTENTRY | r_conv_bit) != (int)R_X86_64_GNU_VTENTRY))
    {
        abort();
    }

    init_table.plt0_pad_byte = 0x90;

    bed = get_elf_backend_data(info->output_bfd);
    htab = elf_x86_hash_table(info, bed->target_id);
    if (!htab)
        abort();

    init_table.lazy_plt = &elf_x86_64_lazy_plt;
    init_table.non_lazy_plt = &elf_x86_64_non_lazy_plt;
    init_table.lazy_ibt_plt = &elf_x86_64_lazy_ibt_plt;
    init_table.non_lazy_ibt_plt = &elf_x86_64_non_lazy_ibt_plt;

    if (ABI_64_P(info->output_bfd)) {
        init_table.sframe_lazy_plt = &elf_x86_64_sframe_plt;
        init_table.sframe_non_lazy_plt = &elf_x86_64_sframe_non_lazy_plt;
        init_table.sframe_lazy_ibt_plt = &elf_x86_64_sframe_ibt_plt;
        init_table.sframe_non_lazy_ibt_plt = &elf_x86_64_sframe_non_lazy_ibt_plt;
        init_table.r_info = elf64_r_info;
        init_table.r_sym = elf64_r_sym;
    } else {
        init_table.sframe_lazy_plt = NULL;
        init_table.sframe_non_lazy_plt = NULL;
        init_table.sframe_lazy_ibt_plt = NULL;
        init_table.sframe_non_lazy_ibt_plt = NULL;
        init_table.r_info = elf32_r_info;
        init_table.r_sym = elf32_r_sym;
    }

    return _bfd_x86_elf_link_setup_gnu_properties(info, &init_table);
}

static void elf_x86_64_add_glibc_version_dependency(struct elf_find_verdep_info *rinfo)
{
    int i = 0, mark_plt = -1;
    const char *version[4] = { NULL };
    bool auto_version[4] = { false };
    struct elf_x86_link_hash_table *htab;

    if (rinfo == NULL || rinfo->info == NULL)
        return;

    if (rinfo->info->enable_dt_relr) {
        version[i++] = "GLIBC_ABI_DT_RELR";
    }

    htab = elf_x86_hash_table(rinfo->info, X86_64_ELF_DATA);
    if (htab != NULL && htab->params != NULL) {
        if (htab->params->gnu2_tls_version_tag && htab->has_tls_desc_call) {
            version[i] = "GLIBC_ABI_GNU2_TLS";
            auto_version[i] = (htab->params->gnu2_tls_version_tag == 2);
            i++;
        }
        if (htab->params->mark_plt) {
            mark_plt = i;
            auto_version[i] = true;
            version[i++] = "GLIBC_ABI_DT_X86_64_PLT";
        }
    }

    if (i == 0)
        return;

    if (!_bfd_elf_link_add_glibc_version_dependency(rinfo, version, auto_version))
        return;

    if (mark_plt < 0 || auto_version[mark_plt])
        return;

    version[0] = "GLIBC_2.36";
    auto_version[0] = false;
    version[1] = NULL;
    _bfd_elf_link_add_glibc_version_dependency(rinfo, version, auto_version);
}

static const struct bfd_elf_special_section
elf_x86_64_special_sections[]=
{
  { STRING_COMMA_LEN (".gnu.linkonce.lb"), -2, SHT_NOBITS,   SHF_ALLOC + SHF_WRITE + SHF_X86_64_LARGE},
  { STRING_COMMA_LEN (".gnu.linkonce.lr"), -2, SHT_PROGBITS, SHF_ALLOC + SHF_X86_64_LARGE},
  { STRING_COMMA_LEN (".gnu.linkonce.lt"), -2, SHT_PROGBITS, SHF_ALLOC + SHF_EXECINSTR + SHF_X86_64_LARGE},
  { STRING_COMMA_LEN (".lbss"),		   -2, SHT_NOBITS,   SHF_ALLOC + SHF_WRITE + SHF_X86_64_LARGE},
  { STRING_COMMA_LEN (".ldata"),	   -2, SHT_PROGBITS, SHF_ALLOC + SHF_WRITE + SHF_X86_64_LARGE},
  { STRING_COMMA_LEN (".lrodata"),	   -2, SHT_PROGBITS, SHF_ALLOC + SHF_X86_64_LARGE},
  { NULL,			0,	    0, 0,	     0 }
};

#define TARGET_LITTLE_SYM		    x86_64_elf64_vec
#define TARGET_LITTLE_NAME		    "elf64-x86-64"
#define ELF_ARCH			    bfd_arch_i386
#define ELF_TARGET_ID			    X86_64_ELF_DATA
#define ELF_MACHINE_CODE		    EM_X86_64
#define ELF_MAXPAGESIZE			    0x1000
#define ELF_COMMONPAGESIZE		    ELF_MAXPAGESIZE

#define elf_backend_can_gc_sections	    1
#define elf_backend_can_refcount	    1
#define elf_backend_want_got_plt	    1
#define elf_backend_plt_readonly	    1
#define elf_backend_want_plt_sym	    0
#define elf_backend_got_header_size	    (GOT_ENTRY_SIZE*3)
#define elf_backend_rela_normal		    1
#define elf_backend_plt_alignment	    4
#define elf_backend_caches_rawsize	    1
#define elf_backend_dtrel_excludes_plt	    1
#define elf_backend_want_dynrelro	    1

#define elf_info_to_howto		    elf_x86_64_info_to_howto

#define bfd_elf64_bfd_copy_private_section_data \
  elf_x86_64_copy_private_section_data
#define bfd_elf64_bfd_reloc_type_lookup	    elf_x86_64_reloc_type_lookup
#define bfd_elf64_bfd_reloc_name_lookup \
  elf_x86_64_reloc_name_lookup

#define elf_backend_relocs_compatible	    elf_x86_64_relocs_compatible
#define elf_backend_early_size_sections	    elf_x86_64_early_size_sections
#define elf_backend_create_dynamic_sections _bfd_elf_create_dynamic_sections
#define elf_backend_finish_dynamic_sections elf_x86_64_finish_dynamic_sections
#define elf_backend_finish_dynamic_symbol   elf_x86_64_finish_dynamic_symbol
#define elf_backend_output_arch_local_syms  elf_x86_64_output_arch_local_syms
#define elf_backend_grok_prstatus	    elf_x86_64_grok_prstatus
#define elf_backend_grok_psinfo		    elf_x86_64_grok_psinfo
#ifdef CORE_HEADER
#define elf_backend_write_core_note	    elf_x86_64_write_core_note
#endif
#define elf_backend_reloc_type_class	    elf_x86_64_reloc_type_class
#define elf_backend_relocate_section	    elf_x86_64_relocate_section
#define elf_backend_init_index_section	    _bfd_elf_init_1_index_section
#define elf_backend_object_p		    elf64_x86_64_elf_object_p
#define bfd_elf64_get_synthetic_symtab	    elf_x86_64_get_synthetic_symtab

#define elf_backend_section_from_shdr \
	elf_x86_64_section_from_shdr

#define elf_backend_section_from_bfd_section \
  elf_x86_64_elf_section_from_bfd_section
#define elf_backend_add_symbol_hook \
  elf_x86_64_add_symbol_hook
#define elf_backend_symbol_processing \
  elf_x86_64_symbol_processing
#define elf_backend_common_section_index \
  elf_x86_64_common_section_index
#define elf_backend_common_section \
  elf_x86_64_common_section
#define elf_backend_common_definition \
  elf_x86_64_common_definition
#define elf_backend_merge_symbol \
  elf_x86_64_merge_symbol
#define elf_backend_special_sections \
  elf_x86_64_special_sections
#define elf_backend_section_flags	    elf_x86_64_section_flags
#define elf_backend_fake_sections	    elf_x86_64_fake_sections
#define elf_backend_additional_program_headers \
  elf_x86_64_additional_program_headers
#define elf_backend_setup_gnu_properties \
  elf_x86_64_link_setup_gnu_properties
#define elf_backend_hide_symbol \
  _bfd_x86_elf_hide_symbol
#define elf_backend_add_glibc_version_dependency \
  elf_x86_64_add_glibc_version_dependency

#undef	elf64_bed
#define elf64_bed elf64_x86_64_bed

#include "elf64-target.h"

#undef elf_backend_add_glibc_version_dependency

/* FreeBSD support.  */

#undef	TARGET_LITTLE_SYM
#define TARGET_LITTLE_SYM		    x86_64_elf64_fbsd_vec
#undef	TARGET_LITTLE_NAME
#define TARGET_LITTLE_NAME		    "elf64-x86-64-freebsd"

#undef	ELF_OSABI
#define	ELF_OSABI			    ELFOSABI_FREEBSD

#undef	elf64_bed
#define elf64_bed elf64_x86_64_fbsd_bed

#include "elf64-target.h"

/* Solaris 2 support.  */

#undef  TARGET_LITTLE_SYM
#define TARGET_LITTLE_SYM		    x86_64_elf64_sol2_vec
#undef  TARGET_LITTLE_NAME
#define TARGET_LITTLE_NAME		    "elf64-x86-64-sol2"

#undef	ELF_MAXPAGESIZE
#define ELF_MAXPAGESIZE			    0x100000

#undef	ELF_TARGET_OS
#define	ELF_TARGET_OS			    is_solaris

/* Restore default: we cannot use ELFOSABI_SOLARIS, otherwise ELFOSABI_NONE
   objects won't be recognized.  */
#undef ELF_OSABI

#undef  elf64_bed
#define elf64_bed			    elf64_x86_64_sol2_bed

/* The 64-bit static TLS arena size is rounded to the nearest 16-byte
   boundary.  */
#undef  elf_backend_static_tls_alignment
#define elf_backend_static_tls_alignment    16

/* The Solaris 2 ABI requires a plt symbol on all platforms.

   Cf. Linker and Libraries Guide, Ch. 2, Link-Editor, Generating the Output
   File, p.63.  */
#undef  elf_backend_want_plt_sym
#define elf_backend_want_plt_sym	    1

#undef  elf_backend_strtab_flags
#define elf_backend_strtab_flags	SHF_STRINGS

static bool elf64_x86_64_copy_solaris_special_section_fields(const bfd *ibfd, bfd *obfd, const Elf_Internal_Shdr *isection, Elf_Internal_Shdr *osection) {
    (void)ibfd;
    (void)obfd;
    (void)isection;
    (void)osection;
    return false;
}

#undef  elf_backend_copy_special_section_fields
#define elf_backend_copy_special_section_fields elf64_x86_64_copy_solaris_special_section_fields

#include "elf64-target.h"

/* Restore defaults.  */
#undef	ELF_OSABI
#undef	elf_backend_static_tls_alignment
#undef	elf_backend_want_plt_sym
#define elf_backend_want_plt_sym	0
#undef  elf_backend_strtab_flags
#undef  elf_backend_copy_special_section_fields

/* 32bit x86-64 support.  */

#undef  TARGET_LITTLE_SYM
#define TARGET_LITTLE_SYM		    x86_64_elf32_vec
#undef  TARGET_LITTLE_NAME
#define TARGET_LITTLE_NAME		    "elf32-x86-64"
#undef	elf32_bed
#define	elf32_bed			    elf32_x86_64_bed

#undef ELF_ARCH
#define ELF_ARCH			    bfd_arch_i386

#undef	ELF_MAXPAGESIZE
#define ELF_MAXPAGESIZE			    0x1000

#undef	ELF_TARGET_OS
#undef	ELF_OSABI

#define bfd_elf32_bfd_copy_private_section_data \
  elf_x86_64_copy_private_section_data
#define bfd_elf32_bfd_reloc_type_lookup	\
  elf_x86_64_reloc_type_lookup
#define bfd_elf32_bfd_reloc_name_lookup \
  elf_x86_64_reloc_name_lookup
#define bfd_elf32_get_synthetic_symtab \
  elf_x86_64_get_synthetic_symtab

#undef elf_backend_object_p
#define elf_backend_object_p \
  elf32_x86_64_elf_object_p

#undef elf_backend_bfd_from_remote_memory
#define elf_backend_bfd_from_remote_memory \
  _bfd_elf32_bfd_from_remote_memory

#undef elf_backend_add_glibc_version_dependency
#define elf_backend_add_glibc_version_dependency \
  elf_x86_64_add_glibc_version_dependency

#undef elf_backend_size_info
#define elf_backend_size_info \
  _bfd_elf32_size_info

#include "elf32-target.h"
