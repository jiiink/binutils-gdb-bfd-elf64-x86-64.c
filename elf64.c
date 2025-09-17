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

static unsigned get_howto_table_index_for_r32(bfd *abfd, unsigned r_type)
{
    if (ABI_64_P(abfd))
        return r_type;
    return ARRAY_SIZE(x86_64_elf_howto_table) - 1;
}

static unsigned get_howto_table_index_for_standard(bfd *abfd, unsigned r_type)
{
    if (r_type >= (unsigned int) R_X86_64_standard)
    {
        _bfd_error_handler(_("%pB: unsupported relocation type %#x"),
                          abfd, r_type);
        bfd_set_error(bfd_error_bad_value);
        return (unsigned) -1;
    }
    return r_type;
}

static unsigned get_howto_table_index(bfd *abfd, unsigned r_type)
{
    if (r_type == (unsigned int) R_X86_64_32)
        return get_howto_table_index_for_r32(abfd, r_type);
    
    if (r_type < (unsigned int) R_X86_64_GNU_VTINHERIT ||
        r_type >= (unsigned int) R_X86_64_max)
        return get_howto_table_index_for_standard(abfd, r_type);
    
    return r_type - (unsigned int) R_X86_64_vt_offset;
}

static reloc_howto_type *
elf_x86_64_rtype_to_howto(bfd *abfd, unsigned r_type)
{
    unsigned i = get_howto_table_index(abfd, r_type);
    
    if (i == (unsigned) -1)
        return NULL;
    
    BFD_ASSERT(x86_64_elf_howto_table[i].type == r_type);
    return &x86_64_elf_howto_table[i];
}

/* Given a BFD reloc type, return a HOWTO structure.  */
static reloc_howto_type *
elf_x86_64_reloc_type_lookup (bfd *abfd,
			      bfd_reloc_code_real_type code)
{
  const size_t map_size = sizeof (x86_64_reloc_map) / sizeof (struct elf_reloc_map);
  
  for (size_t i = 0; i < map_size; i++)
    {
      if (x86_64_reloc_map[i].bfd_reloc_val == code)
	return elf_x86_64_rtype_to_howto (abfd,
					  x86_64_reloc_map[i].elf_reloc_val);
    }
  return NULL;
}

static reloc_howto_type *
get_x32_r_x86_64_32_reloc(void)
{
    reloc_howto_type *reloc = &x86_64_elf_howto_table[ARRAY_SIZE(x86_64_elf_howto_table) - 1];
    BFD_ASSERT(reloc->type == (unsigned int) R_X86_64_32);
    return reloc;
}

static reloc_howto_type *
find_reloc_in_table(const char *r_name)
{
    unsigned int i;
    
    for (i = 0; i < ARRAY_SIZE(x86_64_elf_howto_table); i++)
    {
        if (x86_64_elf_howto_table[i].name != NULL &&
            strcasecmp(x86_64_elf_howto_table[i].name, r_name) == 0)
        {
            return &x86_64_elf_howto_table[i];
        }
    }
    
    return NULL;
}

static reloc_howto_type *
elf_x86_64_reloc_name_lookup(bfd *abfd, const char *r_name)
{
    if (!ABI_64_P(abfd) && strcasecmp(r_name, "R_X86_64_32") == 0)
    {
        return get_x32_r_x86_64_32_reloc();
    }
    
    return find_reloc_in_table(r_name);
}

/* Given an x86_64 ELF reloc type, fill in an arelent structure.  */

static bool
elf_x86_64_info_to_howto (bfd *abfd, arelent *cache_ptr,
			  Elf_Internal_Rela *dst)
{
  unsigned r_type = ELF32_R_TYPE (dst->r_info);
  
  cache_ptr->howto = elf_x86_64_rtype_to_howto (abfd, r_type);
  if (cache_ptr->howto == NULL)
    return false;
    
  BFD_ASSERT (r_type == cache_ptr->howto->type || cache_ptr->howto->type == R_X86_64_NONE);
  return true;
}

/* Support for core dump NOTE sections.  */
static bool
elf_x86_64_grok_prstatus (bfd *abfd, Elf_Internal_Note *note)
{
  #define PRSTATUS_SIZE_X32 296
  #define PRSTATUS_SIZE_X86_64 336
  #define SIGNAL_OFFSET 12
  #define PID_OFFSET_X32 24
  #define PID_OFFSET_X86_64 32
  #define REG_OFFSET_X32 72
  #define REG_OFFSET_X86_64 112
  #define REG_SIZE 216

  int offset;
  size_t size;
  int pid_offset;

  switch (note->descsz)
    {
      default:
	return false;

      case PRSTATUS_SIZE_X32:
	pid_offset = PID_OFFSET_X32;
	offset = REG_OFFSET_X32;
	size = REG_SIZE;
	break;

      case PRSTATUS_SIZE_X86_64:
	pid_offset = PID_OFFSET_X86_64;
	offset = REG_OFFSET_X86_64;
	size = REG_SIZE;
	break;
    }

  elf_tdata (abfd)->core->signal = bfd_get_16 (abfd, note->descdata + SIGNAL_OFFSET);
  elf_tdata (abfd)->core->lwpid = bfd_get_32 (abfd, note->descdata + pid_offset);

  return _bfd_elfcore_make_pseudosection (abfd, ".reg",
					  size, note->descpos + offset);
}

static void extract_psinfo_data(bfd *abfd, const unsigned char *descdata, 
                                int pid_offset, int program_offset, int command_offset)
{
    elf_tdata (abfd)->core->pid = bfd_get_32 (abfd, descdata + pid_offset);
    elf_tdata (abfd)->core->program = _bfd_elfcore_strndup (abfd, descdata + program_offset, 16);
    elf_tdata (abfd)->core->command = _bfd_elfcore_strndup (abfd, descdata + command_offset, 80);
}

static void strip_trailing_space(char *command)
{
    int n = strlen (command);
    if (0 < n && command[n - 1] == ' ')
        command[n - 1] = '\0';
}

#define PSINFO_SIZE_UGID16 124
#define PSINFO_SIZE_UGID32 128
#define PSINFO_SIZE_X86_64 136

#define UGID16_PID_OFFSET 12
#define UGID16_PROGRAM_OFFSET 28
#define UGID16_COMMAND_OFFSET 44

#define UGID32_PID_OFFSET 12
#define UGID32_PROGRAM_OFFSET 32
#define UGID32_COMMAND_OFFSET 48

#define X86_64_PID_OFFSET 24
#define X86_64_PROGRAM_OFFSET 40
#define X86_64_COMMAND_OFFSET 56

static bool
elf_x86_64_grok_psinfo (bfd *abfd, Elf_Internal_Note *note)
{
    switch (note->descsz)
    {
        case PSINFO_SIZE_UGID16:
            extract_psinfo_data(abfd, note->descdata, 
                              UGID16_PID_OFFSET, UGID16_PROGRAM_OFFSET, UGID16_COMMAND_OFFSET);
            break;

        case PSINFO_SIZE_UGID32:
            extract_psinfo_data(abfd, note->descdata, 
                              UGID32_PID_OFFSET, UGID32_PROGRAM_OFFSET, UGID32_COMMAND_OFFSET);
            break;

        case PSINFO_SIZE_X86_64:
            extract_psinfo_data(abfd, note->descdata, 
                              X86_64_PID_OFFSET, X86_64_PROGRAM_OFFSET, X86_64_COMMAND_OFFSET);
            break;

        default:
            return false;
    }

    strip_trailing_space(elf_tdata (abfd)->core->command);
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

static bool
elf64_x86_64_elf_object_p (bfd *abfd)
{
  bfd_default_set_arch_mach (abfd, bfd_arch_i386, bfd_mach_x86_64);
  return true;
}

static bool
elf32_x86_64_elf_object_p (bfd *abfd)
{
  bfd_default_set_arch_mach (abfd, bfd_arch_i386, bfd_mach_x64_32);
  return true;
}

/* Return TRUE if the TLS access code sequence support transition
   from R_TYPE.  */

static bool
check_lea_prefix(bfd_byte *contents, bfd_vma offset, const unsigned char *lea, size_t lea_size)
{
  if (offset < lea_size)
    return false;
  return memcmp(contents + offset - lea_size, lea, lea_size) == 0;
}

static bool
check_largepic_call(bfd_byte *call)
{
  return memcmp(call, "\x48\xb8", 2) == 0
      && call[11] == 0x01
      && call[13] == 0xff
      && call[14] == 0xd0
      && ((call[10] == 0x48 && call[12] == 0xd8)
          || (call[10] == 0x4c && call[12] == 0xf8));
}

static bool
is_valid_gd_call(bfd_byte *call)
{
  return call[0] == 0x66
      && ((call[1] == 0x48 && call[2] == 0xff && call[3] == 0x15)
          || (call[1] == 0x48 && call[2] == 0x67 && call[3] == 0xe8)
          || (call[1] == 0x66 && call[2] == 0x48 && call[3] == 0xe8));
}

static bool
is_valid_ld_call(bfd_byte *call)
{
  return call[0] == 0xe8
      || (call[0] == 0xff && call[1] == 0x15)
      || (call[0] == 0x67 && call[1] == 0xe8);
}

static enum elf_x86_tls_error_type
check_gd_transition(bfd *abfd, asection *sec, bfd_byte *contents, bfd_vma offset, bool *largepic, bool *indirect_call)
{
  static const unsigned char leaq[] = { 0x66, 0x48, 0x8d, 0x3d };
  bfd_byte *call;
  
  if ((offset + 12) > sec->size)
    return elf_x86_tls_error_yes;
  
  call = contents + offset + 4;
  
  if (!is_valid_gd_call(call))
    {
      if (!ABI_64_P(abfd) || (offset + 19) > sec->size || offset < 3)
        return elf_x86_tls_error_yes;
      if (!check_lea_prefix(contents + offset + 4, 7, leaq + 1, 3))
        return elf_x86_tls_error_yes;
      if (!check_largepic_call(call))
        return elf_x86_tls_error_yes;
      *largepic = true;
    }
  else if (ABI_64_P(abfd))
    {
      if (!check_lea_prefix(contents, offset, leaq, 4))
        return elf_x86_tls_error_yes;
    }
  else
    {
      if (!check_lea_prefix(contents, offset, leaq + 1, 3))
        return elf_x86_tls_error_yes;
    }
  
  *indirect_call = call[2] == 0xff;
  return elf_x86_tls_error_none;
}

static enum elf_x86_tls_error_type
check_ld_transition(bfd *abfd, asection *sec, bfd_byte *contents, bfd_vma offset, bool *largepic, bool *indirect_call)
{
  static const unsigned char lea[] = { 0x48, 0x8d, 0x3d };
  bfd_byte *call;
  
  if (offset < 3 || (offset + 9) > sec->size)
    return elf_x86_tls_error_yes;
  
  if (!check_lea_prefix(contents, offset, lea, 3))
    return elf_x86_tls_error_yes;
  
  call = contents + offset + 4;
  
  if (!is_valid_ld_call(call))
    {
      if (!ABI_64_P(abfd) || (offset + 19) > sec->size)
        return elf_x86_tls_error_yes;
      if (!check_largepic_call(call))
        return elf_x86_tls_error_yes;
      *largepic = true;
    }
  
  *indirect_call = call[0] == 0xff;
  return elf_x86_tls_error_none;
}

static enum elf_x86_tls_error_type
validate_tls_get_addr(struct elf_link_hash_entry **sym_hashes,
                      Elf_Internal_Shdr *symtab_hdr,
                      const Elf_Internal_Rela *rel,
                      struct elf_x86_link_hash_table *htab,
                      bool largepic,
                      bool indirect_call)
{
  unsigned long r_symndx;
  struct elf_link_hash_entry *h;
  unsigned int r_type;
  
  r_symndx = htab->r_sym(rel[1].r_info);
  if (r_symndx < symtab_hdr->sh_info)
    return elf_x86_tls_error_yes;
  
  h = sym_hashes[r_symndx - symtab_hdr->sh_info];
  if (h == NULL || !((struct elf_x86_link_hash_entry *)h)->tls_get_addr)
    return elf_x86_tls_error_yes;
  
  r_type = (ELF32_R_TYPE(rel[1].r_info) & ~R_X86_64_converted_reloc_bit);
  
  if (largepic)
    return (r_type == R_X86_64_PLTOFF64) ? elf_x86_tls_error_none : elf_x86_tls_error_yes;
  
  if (indirect_call)
    return (r_type == R_X86_64_GOTPCRELX || r_type == R_X86_64_GOTPCREL)
           ? elf_x86_tls_error_none : elf_x86_tls_error_yes;
  
  return (r_type == R_X86_64_PC32 || r_type == R_X86_64_PLT32)
         ? elf_x86_tls_error_none : elf_x86_tls_error_yes;
}

static enum elf_x86_tls_error_type
check_gottpoff_rex(bfd *abfd, bfd_byte *contents, bfd_vma offset, asection *sec)
{
  unsigned int val;
  
  if (offset >= 3 && (offset + 4) <= sec->size)
    {
      val = bfd_get_8(abfd, contents + offset - 3);
      if (val != 0x48 && val != 0x4c)
        {
          if (ABI_64_P(abfd))
            return elf_x86_tls_error_yes;
        }
    }
  else
    {
      if (ABI_64_P(abfd))
        return elf_x86_tls_error_yes;
      if (offset < 2 || (offset + 3) > sec->size)
        return elf_x86_tls_error_yes;
    }
  
  val = bfd_get_8(abfd, contents + offset - 2);
  if (val != 0x8b && val != 0x03)
    return elf_x86_tls_error_add_mov;
  
  val = bfd_get_8(abfd, contents + offset - 1);
  return ((val & 0xc7) == 5) ? elf_x86_tls_error_none : elf_x86_tls_error_yes;
}

#define CHECK_OFFSET_BOUNDS(offset, min, size, max) \
  ((offset) < (min) || ((offset) + (max)) > (size))

#define CHECK_MODRM_FIELD(val) \
  (((val) & 0xc7) == 5 ? elf_x86_tls_error_none : elf_x86_tls_error_yes)

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
  bool largepic = false;
  bfd_vma offset;
  struct elf_x86_link_hash_table *htab;
  bool indirect_call;
  enum elf_x86_tls_error_type result;
  
  htab = elf_x86_hash_table(info, X86_64_ELF_DATA);
  offset = rel->r_offset;
  
  switch (r_type)
    {
    case R_X86_64_TLSGD:
    case R_X86_64_TLSLD:
      if ((rel + 1) >= relend)
        return elf_x86_tls_error_yes;
      
      if (r_type == R_X86_64_TLSGD)
        {
          result = check_gd_transition(abfd, sec, contents, offset, &largepic, &indirect_call);
          if (result != elf_x86_tls_error_none)
            return result;
        }
      else
        {
          result = check_ld_transition(abfd, sec, contents, offset, &largepic, &indirect_call);
          if (result != elf_x86_tls_error_none)
            return result;
        }
      
      return validate_tls_get_addr(sym_hashes, symtab_hdr, rel, htab, largepic, indirect_call);
      
    case R_X86_64_CODE_4_GOTTPOFF:
      if (CHECK_OFFSET_BOUNDS(offset, 4, sec->size, 4))
        return elf_x86_tls_error_yes;
      
      if (!ABI_64_P(abfd)
          && contents[offset - 4] == 0x0f
          && contents[offset - 3] == 0x38
          && contents[offset - 2] == 0x8b)
        {
          val = bfd_get_8(abfd, contents + offset - 1);
          return CHECK_MODRM_FIELD(val);
        }
      
      if (contents[offset - 4] != 0xd5)
        return elf_x86_tls_error_yes;
      
      val = bfd_get_8(abfd, contents + offset - 2);
      if (val != 0x8b && val != 0x03)
        return elf_x86_tls_error_add_mov;
      
      val = bfd_get_8(abfd, contents + offset - 1);
      return CHECK_MODRM_FIELD(val);
      
    case R_X86_64_CODE_5_GOTTPOFF:
      if (CHECK_OFFSET_BOUNDS(offset, 5, sec->size, 4)
          || (contents[offset - 5] | (ABI_64_P(abfd) ? 7 : 0xf)) != 0x4f
          || contents[offset - 4] != 0x0f
          || contents[offset - 3] != 0x38
          || contents[offset - 2] != 0x8b)
        return elf_x86_tls_error_yes;
      
      val = bfd_get_8(abfd, contents + offset - 1);
      return CHECK_MODRM_FIELD(val);
      
    case R_X86_64_CODE_6_GOTTPOFF:
      if (CHECK_OFFSET_BOUNDS(offset, 6, sec->size, 4)
          || contents[offset - 6] != 0x62)
        return elf_x86_tls_error_yes;
      
      val = bfd_get_8(abfd, contents + offset - 2);
      if (val != 0x01 && val != 0x03 && val != 0x8b)
        return elf_x86_tls_error_add_movrs;
      
      val = bfd_get_8(abfd, contents + offset - 1);
      return CHECK_MODRM_FIELD(val);
      
    case R_X86_64_GOTTPOFF:
      return check_gottpoff_rex(abfd, contents, offset, sec);
      
    case R_X86_64_CODE_4_GOTPC32_TLSDESC:
      if (CHECK_OFFSET_BOUNDS(offset, 4, sec->size, 4)
          || contents[offset - 4] != 0xd5)
        return elf_x86_tls_error_yes;
      
      if (bfd_get_8(abfd, contents + offset - 2) != 0x8d)
        return elf_x86_tls_error_lea;
      
      val = bfd_get_8(abfd, contents + offset - 1);
      return ((val & 0xc7) == 0x05) ? elf_x86_tls_error_none : elf_x86_tls_error_yes;
      
    case R_X86_64_GOTPC32_TLSDESC:
      if (CHECK_OFFSET_BOUNDS(offset, 3, sec->size, 4))
        return elf_x86_tls_error_yes;
      
      val = bfd_get_8(abfd, contents + offset - 3);
      val &= 0xfb;
      if (val != 0x48 && (ABI_64_P(abfd) || val != 0x40))
        return elf_x86_tls_error_yes;
      
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

static bool is_function_symbol(struct elf_link_hash_entry *h)
{
    return h != NULL && (h->type == STT_FUNC || h->type == STT_GNU_IFUNC);
}

static bool is_gottpoff_variant(unsigned int type)
{
    return type == R_X86_64_CODE_4_GOTTPOFF ||
           type == R_X86_64_CODE_5_GOTTPOFF ||
           type == R_X86_64_CODE_6_GOTTPOFF;
}

static bool is_no_transition_needed(unsigned int from_type, unsigned int to_type)
{
    return from_type == to_type ||
           (is_gottpoff_variant(from_type) && to_type == R_X86_64_GOTTPOFF);
}

static bool is_tlsgd_or_tlsdesc_type(unsigned int type)
{
    return type == R_X86_64_TLSGD ||
           type == R_X86_64_GOTPC32_TLSDESC ||
           type == R_X86_64_CODE_4_GOTPC32_TLSDESC ||
           type == R_X86_64_TLSDESC_CALL;
}

static bool validate_tlsdesc_call(bfd *abfd, asection *sec, bfd_byte *contents,
                                  const Elf_Internal_Rela *rel)
{
    bfd_vma offset = rel->r_offset;
    
    if (offset + 2 > sec->size)
        return false;
    
    bfd_byte *call = contents + offset;
    unsigned int prefix = 0;
    
    if (!ABI_64_P(abfd) && call[0] == 0x67)
    {
        prefix = 1;
        if (offset + 3 > sec->size)
            return false;
    }
    
    return call[prefix] == 0xff && call[1 + prefix] == 0x10;
}

static unsigned int determine_executable_to_type(struct elf_link_hash_entry *h,
                                                 unsigned int from_type)
{
    if (h == NULL)
        return R_X86_64_TPOFF32;
    
    switch (from_type)
    {
    case R_X86_64_TLSGD:
    case R_X86_64_GOTPC32_TLSDESC:
    case R_X86_64_CODE_4_GOTPC32_TLSDESC:
    case R_X86_64_GOTTPOFF:
    case R_X86_64_CODE_4_GOTTPOFF:
    case R_X86_64_CODE_5_GOTTPOFF:
    case R_X86_64_CODE_6_GOTTPOFF:
        return R_X86_64_GOTTPOFF;
    default:
        return from_type;
    }
}

static unsigned int apply_relocate_section_transitions(struct bfd_link_info *info,
                                                       struct elf_link_hash_entry *h,
                                                       int tls_type,
                                                       unsigned int to_type)
{
    unsigned int new_to_type = to_type;
    
    if (TLS_TRANSITION_IE_TO_LE_P(info, h, tls_type))
        new_to_type = R_X86_64_TPOFF32;
    
    if (is_tlsgd_or_tlsdesc_type(to_type) && tls_type == GOT_TLS_IE)
        new_to_type = R_X86_64_GOTTPOFF;
    
    return new_to_type;
}

static bool should_check_transition(unsigned int from_type,
                                    unsigned int old_to_type,
                                    unsigned int new_to_type)
{
    if (new_to_type == old_to_type)
        return false;
    
    return from_type == old_to_type || is_no_transition_needed(from_type, old_to_type);
}

static bool report_transition_error(struct bfd_link_info *info, bfd *abfd,
                                   asection *sec, Elf_Internal_Shdr *symtab_hdr,
                                   struct elf_link_hash_entry *h,
                                   Elf_Internal_Sym *sym,
                                   const Elf_Internal_Rela *rel,
                                   unsigned int from_type,
                                   unsigned int to_type,
                                   enum elf_x86_tls_error_type tls_error)
{
    reloc_howto_type *from = &x86_64_elf_howto_table[from_type];
    reloc_howto_type *to = &x86_64_elf_howto_table[to_type];
    
    if (from == NULL || to == NULL)
        return false;
    
    _bfd_x86_elf_link_report_tls_transition_error(info, abfd, sec, symtab_hdr,
                                                  h, sym, rel, from->name,
                                                  to->name, tls_error);
    return false;
}

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
    
    if (is_function_symbol(h))
        return true;
    
    switch (from_type)
    {
    case R_X86_64_TLSDESC_CALL:
        if (!validate_tlsdesc_call(abfd, sec, contents, rel))
        {
            _bfd_x86_elf_link_report_tls_transition_error(info, abfd, sec,
                symtab_hdr, h, sym, rel, "R_X86_64_TLSDESC_CALL", NULL,
                elf_x86_tls_error_indirect_call);
            return false;
        }
        
    case R_X86_64_TLSGD:
    case R_X86_64_GOTPC32_TLSDESC:
    case R_X86_64_CODE_4_GOTPC32_TLSDESC:
    case R_X86_64_GOTTPOFF:
    case R_X86_64_CODE_4_GOTTPOFF:
    case R_X86_64_CODE_5_GOTTPOFF:
    case R_X86_64_CODE_6_GOTTPOFF:
        if (bfd_link_executable(info))
            to_type = determine_executable_to_type(h, from_type);
        
        if (from_relocate_section)
        {
            unsigned int new_to_type = apply_relocate_section_transitions(info, h,
                                                                         tls_type,
                                                                         to_type);
            check = should_check_transition(from_type, to_type, new_to_type);
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
    
    if (is_no_transition_needed(from_type, to_type))
        return true;
    
    if (check)
    {
        enum elf_x86_tls_error_type tls_error = elf_x86_64_check_tls_transition(
            abfd, info, sec, contents, symtab_hdr, sym_hashes, from_type, rel, relend);
        
        if (tls_error != elf_x86_tls_error_none)
            return report_transition_error(info, abfd, sec, symtab_hdr, h, sym,
                                          rel, from_type, to_type, tls_error);
    }
    
    *r_type = to_type;
    return true;
}

static const char* get_visibility_string(struct elf_link_hash_entry *h)
{
    switch (ELF_ST_VISIBILITY (h->other))
    {
    case STV_HIDDEN:
        return _("hidden symbol ");
    case STV_INTERNAL:
        return _("internal symbol ");
    case STV_PROTECTED:
        return _("protected symbol ");
    default:
        if (((struct elf_x86_link_hash_entry *) h)->def_protected)
            return _("protected symbol ");
        return _("symbol ");
    }
}

static bool should_use_default_pic(struct elf_link_hash_entry *h)
{
    int visibility = ELF_ST_VISIBILITY (h->other);
    return visibility != STV_HIDDEN && 
           visibility != STV_INTERNAL && 
           visibility != STV_PROTECTED;
}

static const char* get_undefined_string(struct elf_link_hash_entry *h)
{
    if (!SYMBOL_DEFINED_NON_SHARED_P (h) && !h->def_dynamic)
        return _("undefined ");
    return "";
}

static const char* get_symbol_name(struct elf_link_hash_entry *h, 
                                  bfd *input_bfd,
                                  Elf_Internal_Shdr *symtab_hdr,
                                  Elf_Internal_Sym *isym)
{
    if (h)
        return h->root.root.string;
    return bfd_elf_sym_name (input_bfd, symtab_hdr, isym, NULL);
}

static void get_object_and_pic_strings(struct bfd_link_info *info,
                                      const char **object,
                                      const char **pic,
                                      bool use_default_pic)
{
    if (bfd_link_dll (info))
    {
        *object = _("a shared object");
        if (use_default_pic)
            *pic = _("; recompile with -fPIC");
    }
    else if (bfd_link_pie (info))
    {
        *object = _("a PIE object");
        if (use_default_pic)
            *pic = _("; recompile with -fPIE");
    }
    else
    {
        *object = _("a PDE object");
        if (use_default_pic)
            *pic = _("; recompile with -fPIE");
    }
}

static bool
elf_x86_64_need_pic (struct bfd_link_info *info,
                    bfd *input_bfd, asection *sec,
                    struct elf_link_hash_entry *h,
                    Elf_Internal_Shdr *symtab_hdr,
                    Elf_Internal_Sym *isym,
                    reloc_howto_type *howto)
{
    const char *v = "";
    const char *und = "";
    const char *pic = "";
    const char *object;
    bool use_default_pic = true;

    if (h)
    {
        v = get_visibility_string(h);
        use_default_pic = should_use_default_pic(h);
        und = get_undefined_string(h);
    }

    const char *name = get_symbol_name(h, input_bfd, symtab_hdr, isym);
    
    if (!use_default_pic)
        pic = NULL;
    
    get_object_and_pic_strings(info, &object, &pic, use_default_pic && !pic);

    _bfd_error_handler (_("%pB: relocation %s against %s%s`%s' can "
                        "not be used when making %s%s"),
                      input_bfd, howto->name, und, v, name,
                      object, pic);
    bfd_set_error (bfd_error_bad_value);
    sec->check_relocs_failed = 1;
    return false;
}

/* Move the R bits to the B bits in EVEX payload byte 1.  */
static unsigned int evex_move_r_to_b(unsigned int byte1, bool copy)
{
    const unsigned int R3_BIT = 1 << 7;
    const unsigned int R4_BIT = 1 << 4;
    const unsigned int B3_BIT = 1 << 5;
    const unsigned int B4_BIT = 1 << 3;
    const unsigned int R3_TO_B3_SHIFT = 2;
    const unsigned int R4_TO_B4_SHIFT = 1;
    
    byte1 = (byte1 & ~B3_BIT) | ((byte1 & R3_BIT) >> R3_TO_B3_SHIFT);
    byte1 = (byte1 & ~B4_BIT) | ((~byte1 & R4_BIT) >> R4_TO_B4_SHIFT);
    
    if (!copy)
        byte1 |= R4_BIT | R3_BIT;
    
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

#define NOP_OPCODE 0x90
#define ADDR_PREFIX_OPCODE 0x67
#define REX_W 0x08
#define REX_R 0x04
#define REX2_M 0x01

static bool check_offset_bounds(bfd_vma roff, unsigned int min_offset) {
    return roff >= min_offset;
}

static bool is_rex2_instruction(bfd *abfd, bfd_byte *contents, bfd_vma roff) {
    unsigned int opcode = bfd_get_8(abfd, contents + roff - 4);
    if (opcode == 0xd5)
        return true;
    if (opcode != 0x0f)
        return false;
    return bfd_get_8(abfd, contents + roff - 3) == 0x38 &&
           bfd_get_8(abfd, contents + roff - 2) == 0x8b;
}

static bool is_rex_prefixed_movrs(bfd *abfd, bfd_byte *contents, bfd_vma roff) {
    return (bfd_get_8(abfd, contents + roff - 5) | 0xf) == 0x4f &&
           bfd_get_8(abfd, contents + roff - 4) == 0x0f &&
           bfd_get_8(abfd, contents + roff - 3) == 0x38 &&
           bfd_get_8(abfd, contents + roff - 2) == 0x8b;
}

static bool is_evex_map4_np_instruction(unsigned char *evex) {
    return (evex[0] & 7) == 4 && (evex[1] & 3) == 0 && (evex[2] & 0xe0) == 0;
}

static bool validate_relocation_type(unsigned int r_type, bfd_vma roff, 
                                    bfd *abfd, bfd_byte *contents,
                                    unsigned char *evex, bool *relocx) {
    switch (r_type) {
    default:
        if (!check_offset_bounds(roff, 2))
            return false;
        *relocx = (r_type == R_X86_64_GOTPCRELX);
        return true;
        
    case R_X86_64_REX_GOTPCRELX:
        if (!check_offset_bounds(roff, 3))
            return false;
        *relocx = true;
        return true;
        
    case R_X86_64_CODE_4_GOTPCRELX:
        if (!check_offset_bounds(roff, 4))
            return false;
        if (!is_rex2_instruction(abfd, contents, roff))
            return false;
        *relocx = true;
        return true;
        
    case R_X86_64_CODE_5_GOTPCRELX:
        if (!check_offset_bounds(roff, 5))
            return false;
        if (!is_rex_prefixed_movrs(abfd, contents, roff))
            return false;
        *relocx = true;
        return true;
        
    case R_X86_64_CODE_6_GOTPCRELX:
        if (!check_offset_bounds(roff, 6))
            return false;
        if (bfd_get_8(abfd, contents + roff - 6) != 0x62)
            return false;
        evex[0] = bfd_get_8(abfd, contents + roff - 5);
        evex[1] = bfd_get_8(abfd, contents + roff - 4);
        evex[2] = bfd_get_8(abfd, contents + roff - 3);
        if (!is_evex_map4_np_instruction(evex))
            return false;
        *relocx = true;
        return true;
    }
}

static bool is_branch_instruction(unsigned int opcode, unsigned int modrm) {
    if (opcode != 0xff)
        return false;
    unsigned int op = modrm & 0x38;
    return op == 0x10 || op == 0x20;
}

static bool is_push_instruction(unsigned int opcode, unsigned int modrm) {
    return opcode == 0xff && (modrm & 0x38) == 0x30;
}

static void get_symbol_info(bfd *abfd, struct elf_x86_link_hash_table *htab,
                           unsigned int r_symndx, struct elf_link_hash_entry *h,
                           Elf_Internal_Sym **isym, asection **tsec,
                           bool *abs_symbol, bfd_vma *abs_relocation,
                           bool *local_ref, struct bfd_link_info *link_info) {
    if (h == NULL) {
        *isym = bfd_sym_from_r_symndx(&htab->elf.sym_cache, abfd, r_symndx);
        if ((*isym)->st_shndx == SHN_UNDEF) {
            *tsec = NULL;
            return;
        }
        *local_ref = true;
        if ((*isym)->st_shndx == SHN_ABS) {
            *tsec = bfd_abs_section_ptr;
            *abs_symbol = true;
            *abs_relocation = (*isym)->st_value;
        } else if ((*isym)->st_shndx == SHN_COMMON) {
            *tsec = bfd_com_section_ptr;
        } else if ((*isym)->st_shndx == SHN_X86_64_LCOMMON) {
            *tsec = &_bfd_elf_large_com_section;
        } else {
            *tsec = bfd_section_from_elf_index(abfd, (*isym)->st_shndx);
        }
    } else {
        struct elf_x86_link_hash_entry *eh = elf_x86_hash_entry(h);
        *isym = NULL;
        *abs_symbol = ABS_SYMBOL_P(h);
        *abs_relocation = h->root.u.def.value;
        *local_ref = SYMBOL_REFERENCES_LOCAL_P(link_info, h);
        
        if ((h->start_stop || eh->linker_def ||
            ((h->def_regular || h->root.type == bfd_link_hash_defined ||
              h->root.type == bfd_link_hash_defweak) &&
             h != htab->elf.hdynamic && *local_ref))) {
            if (h->start_stop) {
                *tsec = h->root.u.def.section;
            } else if (h == htab->elf.hehdr_start) {
                asection *sec;
                *tsec = NULL;
                for (sec = link_info->output_bfd->sections; sec != NULL; sec = sec->next)
                    if ((sec->flags & SEC_LOAD) != 0 && (*tsec == NULL || (*tsec)->vma > sec->vma))
                        *tsec = sec;
            } else if (h->def_regular && (h->root.type == bfd_link_hash_new ||
                      h->root.type == bfd_link_hash_undefined ||
                      ((h->root.type == bfd_link_hash_defined ||
                        h->root.type == bfd_link_hash_defweak) &&
                       h->root.u.def.section == bfd_und_section_ptr))) {
                *tsec = NULL;
            } else {
                *tsec = h->root.u.def.section;
            }
        } else {
            *tsec = NULL;
        }
    }
}

static bfd_vma compute_relocation(struct elf_link_hash_entry *h,
                                 Elf_Internal_Sym *isym,
                                 asection *tsec,
                                 Elf_Internal_Rela *irel,
                                 bfd_signed_vma *raddend,
                                 struct bfd_link_info *link_info) {
    if (h == NULL) {
        Elf_Internal_Rela rel = *irel;
        bfd_vma relocation = _bfd_elf_rela_local_sym(link_info->output_bfd, isym, &tsec, &rel);
        *raddend = rel.r_addend;
        return relocation;
    } else if (tsec != NULL) {
        return h->root.u.def.value + tsec->output_section->vma + tsec->output_offset;
    }
    return 0;
}

static bool check_relocation_overflow(bfd *abfd, asection *input_section,
                                     bfd_byte *contents, Elf_Internal_Rela *irel,
                                     bfd_vma relocation, bfd_signed_vma raddend,
                                     unsigned int r_type) {
    reloc_howto_type *howto = (r_type == R_X86_64_PC32) ?
                              &x86_64_elf_howto_table[r_type] :
                              elf_x86_64_rtype_to_howto(abfd, r_type);
    bfd_reloc_status_type r = _bfd_final_link_relocate(howto, abfd, input_section,
                                                       contents, irel->r_offset,
                                                       relocation, r_type == R_X86_64_PC32 ? raddend : 0);
    return r == bfd_reloc_overflow;
}

static bool check_abs_relocation_fits(bfd_vma abs_relocation, unsigned int r_type) {
    if (r_type == R_X86_64_32S)
        return (abs_relocation + 0x80000000) <= 0xffffffff;
    return abs_relocation <= 0xffffffff;
}

static void convert_branch_instruction(bfd *abfd, bfd_byte *contents,
                                      Elf_Internal_Rela *irel,
                                      unsigned int modrm,
                                      struct elf_x86_link_hash_table *htab,
                                      struct elf_link_hash_entry *h) {
    unsigned int nop;
    bfd_vma nop_offset;
    
    if (modrm == 0x25) {
        modrm = 0xe9;
        nop = NOP_OPCODE;
        nop_offset = irel->r_offset + 3;
        unsigned int disp = bfd_get_32(abfd, contents + irel->r_offset);
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
                unsigned int disp = bfd_get_32(abfd, contents + irel->r_offset);
                irel->r_offset -= 1;
                bfd_put_32(abfd, disp, contents + irel->r_offset);
            } else {
                nop_offset = irel->r_offset - 2;
            }
        }
    }
    bfd_put_8(abfd, nop, contents + nop_offset);
    bfd_put_8(abfd, modrm, contents + irel->r_offset - 1);
}

static unsigned char evex_move_r_to_b(unsigned char evex0, bool condition) {
    if (!condition)
        return evex0;
    return evex0 | 0x10;
}

static bool convert_evex_instruction(bfd *abfd, bfd_byte *contents,
                                    bfd_vma roff, unsigned int opcode,
                                    unsigned int modrm, unsigned char *evex,
                                    Elf_Internal_Rela *irel,
                                    bfd_vma relocation, bfd_vma abs_relocation,
                                    unsigned int *r_type) {
    bool move_v_r = false;
    
    if (opcode == 0x85) {
        modrm = 0xc0 | (modrm & 0x38) >> 3;
        opcode = 0xf7;
    } else if ((opcode | 0x3a) == 0x3b) {
        if (!(evex[2] & 0x10) && (opcode | 0x38) != 0x3b)
            return false;
        if ((evex[2] & 0x10) && (opcode | 0x38) != 0x3b &&
            (opcode == 0x19 || opcode == 0x29))
            return false;
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
    } else {
        return false;
    }
    
    *r_type = evex[1] & 0x80 ? R_X86_64_32S : R_X86_64_32;
    
    if (check_relocation_overflow(abfd, NULL, contents, irel, relocation, 0, *r_type))
        return false;
    
    if (abs_relocation && !check_abs_relocation_fits(abs_relocation, *r_type))
        return false;
    
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
    return true;
}

static void extract_rex_info(bfd *abfd, bfd_byte *contents, bfd_vma roff,
                            unsigned int r_type, unsigned int *rex,
                            unsigned int *rex2, bool *rex_w, unsigned int *movrs) {
    *rex = 0;
    *rex2 = 0;
    *rex_w = false;
    *movrs = 0;
    
    if (r_type == R_X86_64_CODE_6_GOTPCRELX) {
        unsigned int p = bfd_get_8(abfd, contents + roff - 5);
        if (!(p & 0x80))
            *rex2 |= REX_R;
        if (!(p & 0x10))
            *rex2 |= REX_R << 4;
        if (bfd_get_8(abfd, contents + roff - 4) & 0x80) {
            *rex2 |= REX_W;
            *rex_w = true;
        }
        *movrs = 6;
    } else if (r_type == R_X86_64_CODE_5_GOTPCRELX) {
        *rex = bfd_get_8(abfd, contents + roff - 5);
        *rex_w = (*rex & REX_W) != 0;
        *movrs = 5;
    } else if (r_type == R_X86_64_CODE_4_GOTPCRELX) {
        if (bfd_get_8(abfd, contents + roff - 4) == 0xd5) {
            *rex2 = bfd_get_8(abfd, contents + roff - 3) | 0x100;
            *rex_w = (*rex2 & REX_W) != 0;
        } else if (bfd_get_8(abfd, contents + roff - 4) == 0x0f) {
            *movrs = 4;
        }
    } else if (r_type == R_X86_64_REX_GOTPCRELX) {
        *rex = bfd_get_8(abfd, contents + roff - 3);
        *rex_w = (*rex & REX_W) != 0;
    }
}

static void convert_push_instruction(bfd *abfd, bfd_byte *contents, bfd_vma roff,
                                    unsigned int rex, unsigned int rex2) {
    bfd_put_8(abfd, 0x68, contents + roff - 1);
    if (rex) {
        bfd_put_8(abfd, 0x2e, contents + roff - 3);
        bfd_put_8(abfd, rex, contents + roff - 2);
    } else if (rex2) {
        bfd_put_8(abfd, 0x2e, contents + roff - 4);
        bfd_put_8(abfd, 0xd5, contents + roff - 3);
        bfd_put_8(abfd, rex2, contents + roff - 2);
    } else {
        bfd_put_8(abfd, 0x2e, contents + roff - 2);
    }
}

static void apply_movrs_fixup(bfd *abfd, bfd_byte *contents, bfd_vma roff,
                             unsigned int movrs, unsigned int rex2) {
    if (!movrs)
        return;
    bfd_put_8(abfd, 0x2e, contents + roff - movrs);
    bfd_put_8(abfd, 0x2e, contents + roff - movrs + 1);
    if (movrs == 6) {
        bfd_put_8(abfd, 0xd5, contents + roff - 4);
        bfd_put_8(abfd, rex2, contents + roff - 3);
    }
}

static bool
elf_x86_64_convert_load_reloc(bfd *abfd,
                             asection *input_section,
                             bfd_byte *contents,
                             unsigned int *r_type_p,
                             Elf_Internal_Rela *irel,
                             struct elf_link_hash_entry *h,
                             bool *converted,
                             struct bfd_link_info *link_info) {
    struct elf_x86_link_hash_table *htab;
    bool is_pic, no_overflow, relocx, is_branch = false;
    bool to_reloc_pc32, abs_symbol, local_ref;
    asection *tsec = NULL;
    bfd_signed_vma raddend;
    unsigned int opcode, modrm;
    unsigned char evex[3] = {0, 0, 0};
    unsigned int r_type = *r_type_p;
    unsigned int r_symndx;
    bfd_vma roff = irel->r_offset;
    bfd_vma abs_relocation, relocation;
    Elf_Internal_Sym *isym;
    
    if (!validate_relocation_type(r_type, roff, abfd, contents, evex, &relocx))
        return true;
    
    raddend = irel->r_addend;
    if (raddend != -4)
        return true;
    
    htab = elf_x86_hash_table(link_info, X86_64_ELF_DATA);
    is_pic = bfd_link_pic(link_info);
    no_overflow = link_info->disable_target_specific_optimizations > 1;
    r_symndx = htab->r_sym(irel->r_info);
    
    opcode = bfd_get_8(abfd, contents + roff - 2);
    modrm = bfd_get_8(abfd, contents + roff - 1);
    
    if (opcode == 0xff) {
        if (is_branch_instruction(opcode, modrm)) {
            is_branch = true;
        } else if (!is_push_instruction(opcode, modrm)) {
            return true;
        }
    }
    
    if (opcode != 0x8b && !relocx)
        return true;
    
    to_reloc_pc32 = is_branch || !relocx || no_overflow || is_pic;
    abs_symbol = false;
    abs_relocation = 0;
    
    get_symbol_info(abfd, htab, r_symndx, h, &isym, &tsec,
                   &abs_symbol, &abs_relocation, &local_ref, link_info);
    
    if (h == NULL && isym && isym->st_shndx == SHN_UNDEF)
        return true;
    
    if (h != NULL) {
        struct elf_x86_link_hash_entry *eh = elf_x86_hash_entry(h);
        if ((relocx || opcode == 0x8b) &&
            h->root.type == bfd_link_hash_undefweak &&
            !eh->linker_def && local_ref) {
            if (is_branch) {
                if (no_overflow)
                    return true;
            } else if (relocx) {
                to_reloc_pc32 = false;
            }
            if (to_reloc_pc32 && is_pic)
                return true;
            goto convert;
        }
        if (!h->start_stop && !eh->linker_def && !h->def_regular &&
            h->root.type != bfd_link_hash_defined &&
            h->root.type != bfd_link_hash_defweak) {
            return true;
        }
        if (!local_ref || h == htab->elf.hdynamic) {
            return true;
        }
        if ((h->start_stop || eh->linker_def ||
            (h->def_regular && (h->root.type == bfd_link_hash_new ||
             h->root.type == bfd_link_hash_undefined ||
             ((h->root.type == bfd_link_hash_defined ||
               h->root.type == bfd_link_hash_defweak) &&
              h->root.u.def.section == bfd_und_section_ptr)))) &&
            no_overflow) {
            return true;
        }
    }
    
    if (tsec == NULL)
        return false;
    
    if (elf_section_data(tsec) != NULL &&
        (elf_section_flags(tsec) & SHF_X86_64_LARGE) != 0)
        return true;
    
    if (no_overflow)
        return true;
    
convert:
    relocation = compute_relocation(h, isym, tsec, irel, &raddend, link_info);
    
    if (is_branch) {
        r_type = R_X86_64_PC32;
        if (check_relocation_overflow(abfd, input_section, contents, irel,
                                     relocation, raddend, r_type))
            return true;
        convert_branch_instruction(abfd, contents, irel, modrm, htab, h);
    } else if (r_type == R_X86_64_CODE_6_GOTPCRELX && opcode != 0x8b) {
        if (to_reloc_pc32)
            return true;
        if (!convert_evex_instruction(abfd, contents, roff, opcode, modrm,
                                     evex, irel, relocation, abs_relocation, &r_type))
            return true;
    } else {
        unsigned int rex = 0, rex2 = 0, movrs = 0;
        bool rex_w = false;
        unsigned int rex_mask = REX_R;
        unsigned int rex2_mask = REX_R | REX_R << 4;
        
        extract_rex_info(abfd, contents, roff, r_type, &rex, &rex2, &rex_w, &movrs);
        
        if (opcode == 0x8b) {
            if (abs_symbol && local_ref && relocx)
                to_reloc_pc32 = false;
            
            if (to_reloc_pc32) {
                opcode = 0x8d;
                r_type = R_X86_64_PC32;
                if (check_relocation_overflow(abfd, input_section, contents, irel,
                                            relocation, raddend, r_type))
                    return true;
                if (movrs == 5)
                    bfd_put_8(abfd, rex, contents + roff - 3);
            } else {
                opcode = 0xc7;
                modrm = 0xc0 | (modrm & 0x38) >> 3;
                if (rex_w && ABI_64_P(link_info->output_bfd)) {
                    r_type = R_X86_64_32S;
                } else {
                    r_type = R_X86_64_32;
                    rex_mask |= REX_W;
                    rex2_mask |= REX_W;
                }
                goto rewrite_modrm_rex;
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
                convert_push_instruction(abfd, contents, roff, rex, rex2);
                r_type = R_X86_64_32S;
                irel->r_addend = 0;
                goto finish;
            } else {
                return true;
            }
            
            r_type = rex_w ? R_X86_64_32S : R_X86_64_32;
            
        rewrite_modrm_rex:
            if (check_relocation_overflow(abfd, input_section, contents, irel,
                                        relocation, 0, r_type))
                return true;
            
            if (abs_relocation && !check_abs_relocation_fits(abs_relocation, r_type))
                return true;
            
            bfd_put_8(abfd, modrm, contents + roff - 1);
            
            if (rex) {
                rex = (rex & ~rex_mask) | (rex & REX_R) >> 2;
                bfd_put_8(abfd, rex, contents + roff - 3);
            } else if (rex2) {
                rex2 = ((rex2 & ~rex2_mask) | (rex2 & (REX_R | REX_R << 4)) >> 2);
                bfd_put_8(abfd, rex2, contents + roff - 3);
            }
            
            irel->r_addend = 0;
        }
        
        bfd_put_8(abfd, opcode, contents + roff - 2);
        apply_movrs_fixup(abfd, contents, roff, movrs, rex2);
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

static bool
validate_symbol_index(bfd *abfd, unsigned int r_symndx, Elf_Internal_Shdr *symtab_hdr)
{
  if (r_symndx >= NUM_SHDR_ENTRIES (symtab_hdr))
    {
      _bfd_error_handler (_("%pB: bad symbol index: %d"), abfd, r_symndx);
      return false;
    }
  return true;
}

static bool
validate_relocation(bfd *abfd, asection *sec, unsigned int r_type, const Elf_Internal_Rela *rel)
{
  reloc_howto_type *howto = elf_x86_64_rtype_to_howto (abfd, r_type);
  if (howto == NULL)
    {
      _bfd_error_handler (_("%pB: unsupported relocation type %#x"), abfd, r_type);
      return false;
    }
  if (!bfd_reloc_offset_in_range (howto, abfd, sec, rel->r_offset))
    {
      _bfd_error_handler
        (_("%pB: bad reloc offset (%#" PRIx64 " > %#" PRIx64 ") for"
           " section `%pA'"), abfd, (uint64_t) rel->r_offset,
         (uint64_t) sec->size, sec);
      return false;
    }
  return true;
}

static const char *
get_symbol_name(bfd *abfd, Elf_Internal_Shdr *symtab_hdr, 
                struct elf_link_hash_entry *h, Elf_Internal_Sym *isym)
{
  if (h)
    return h->root.root.string;
  else
    return bfd_elf_sym_name (abfd, symtab_hdr, isym, NULL);
}

static bool
check_x32_relocation(bfd *abfd, unsigned int r_type, Elf_Internal_Shdr *symtab_hdr,
                     struct elf_link_hash_entry *h, Elf_Internal_Sym *isym)
{
  if (ABI_64_P (abfd))
    return true;

  switch (r_type)
    {
    case R_X86_64_DTPOFF64:
    case R_X86_64_TPOFF64:
    case R_X86_64_PC64:
    case R_X86_64_GOTOFF64:
    case R_X86_64_GOT64:
    case R_X86_64_GOTPCREL64:
    case R_X86_64_GOTPC64:
    case R_X86_64_GOTPLT64:
    case R_X86_64_PLTOFF64:
      {
        const char *name = get_symbol_name(abfd, symtab_hdr, h, isym);
        _bfd_error_handler
          (_("%pB: relocation %s against symbol `%s' isn't "
             "supported in x32 mode"), abfd,
           x86_64_elf_howto_table[r_type].name, name);
        bfd_set_error (bfd_error_bad_value);
        return false;
      }
    default:
      break;
    }
  return true;
}

static struct elf_link_hash_entry *
process_local_symbol(struct elf_x86_link_hash_table *htab, bfd *abfd,
                    const Elf_Internal_Rela *rel, Elf_Internal_Shdr *symtab_hdr,
                    Elf_Internal_Sym *isym)
{
  struct elf_link_hash_entry *h = NULL;
  
  if (ELF_ST_TYPE (isym->st_info) == STT_GNU_IFUNC)
    {
      h = _bfd_elf_x86_get_local_sym_hash (htab, abfd, rel, true);
      if (h == NULL)
        return NULL;

      h->root.root.string = bfd_elf_sym_name (abfd, symtab_hdr, isym, NULL);
      h->type = STT_GNU_IFUNC;
      h->def_regular = 1;
      h->ref_regular = 1;
      h->forced_local = 1;
      h->root.type = bfd_link_hash_defined;
    }
  return h;
}

static int
determine_tls_type(unsigned int r_type, struct elf_link_hash_entry *h, 
                   Elf_Internal_Sym *isym)
{
  switch (r_type)
    {
    case R_X86_64_TLSGD:
      return GOT_TLS_GD;
    case R_X86_64_GOTTPOFF:
    case R_X86_64_CODE_4_GOTTPOFF:
    case R_X86_64_CODE_5_GOTTPOFF:
    case R_X86_64_CODE_6_GOTTPOFF:
      return GOT_TLS_IE;
    case R_X86_64_GOTPC32_TLSDESC:
    case R_X86_64_CODE_4_GOTPC32_TLSDESC:
    case R_X86_64_TLSDESC_CALL:
      return GOT_TLS_GDESC;
    default:
      if (h && ABS_SYMBOL_P (h))
        return GOT_ABS;
      else if (!h && isym && isym->st_shndx == SHN_ABS)
        return GOT_ABS;
      return GOT_NORMAL;
    }
}

static bool
merge_tls_types(int old_tls_type, int *tls_type)
{
  if (old_tls_type == *tls_type || old_tls_type == GOT_UNKNOWN)
    return true;
    
  if (GOT_TLS_GD_ANY_P (old_tls_type) && *tls_type == GOT_TLS_IE)
    {
      *tls_type = old_tls_type;
      return true;
    }
    
  if (old_tls_type == GOT_TLS_IE && GOT_TLS_GD_ANY_P (*tls_type))
    {
      *tls_type = old_tls_type;
      return true;
    }
    
  if (GOT_TLS_GD_ANY_P (old_tls_type) && GOT_TLS_GD_ANY_P (*tls_type))
    {
      *tls_type |= old_tls_type;
      return true;
    }
    
  return false;
}

static bool
handle_got_relocation(bfd *abfd, struct elf_x86_link_hash_table *htab,
                      Elf_Internal_Shdr *symtab_hdr, unsigned int r_type,
                      unsigned int r_symndx, struct elf_link_hash_entry *h,
                      struct elf_x86_link_hash_entry *eh, Elf_Internal_Sym *isym)
{
  int tls_type, old_tls_type;
  
  tls_type = determine_tls_type(r_type, h, isym);

  if (h != NULL)
    {
      h->got.refcount = 1;
      old_tls_type = eh->tls_type;
    }
  else
    {
      bfd_signed_vma *local_got_refcounts;

      if (!elf_x86_allocate_local_got_info (abfd, symtab_hdr->sh_info))
        return false;

      local_got_refcounts = elf_local_got_refcounts (abfd);
      local_got_refcounts[r_symndx] = 1;
      old_tls_type = elf_x86_local_got_tls_type (abfd) [r_symndx];
    }

  if (!merge_tls_types(old_tls_type, &tls_type))
    {
      const char *name = get_symbol_name(abfd, symtab_hdr, h, isym);
      _bfd_error_handler
        (_("%pB: '%s' accessed both as normal and thread local symbol"),
         abfd, name);
      bfd_set_error (bfd_error_bad_value);
      return false;
    }

  if (old_tls_type != tls_type)
    {
      if (eh != NULL)
        eh->tls_type = tls_type;
      else
        elf_x86_local_got_tls_type (abfd) [r_symndx] = tls_type;
    }
    
  return true;
}

static bool
is_gotpcrel_relocation(unsigned int r_type)
{
  return (r_type == R_X86_64_GOTPCREL
          || r_type == R_X86_64_GOTPCRELX
          || r_type == R_X86_64_REX_GOTPCRELX
          || r_type == R_X86_64_CODE_4_GOTPCRELX
          || r_type == R_X86_64_CODE_5_GOTPCRELX
          || r_type == R_X86_64_CODE_6_GOTPCRELX);
}

static bool
needs_overflow_check(struct elf_x86_link_hash_table *htab, 
                     struct bfd_link_info *info, asection *sec,
                     struct elf_link_hash_entry *h, bool converted_reloc)
{
  return (!htab->params->no_reloc_overflow_check
          && !converted_reloc
          && (bfd_link_pic (info)
              || (bfd_link_executable (info)
                  && h != NULL
                  && !h->def_regular
                  && h->def_dynamic
                  && (sec->flags & SEC_READONLY) == 0)));
}

static void
handle_pc32_relocation(asection *sec, struct bfd_link_info *info,
                       struct elf_link_hash_entry *h)
{
  if ((sec->flags & SEC_CODE) == 0)
    {
      h->pointer_equality_needed = 1;
      if (bfd_link_pie (info)
          && h->type == STT_FUNC
          && !h->def_regular
          && h->def_dynamic)
        {
          h->needs_plt = 1;
          h->plt.refcount = 1;
        }
    }
}

static bool
is_64bit_relocation(unsigned int r_type)
{
  return (r_type == R_X86_64_64 || r_type == R_X86_64_PC64);
}

static bool
is_32bit_relocation(unsigned int r_type)
{
  return (r_type == R_X86_64_32 || r_type == R_X86_64_32S);
}

static void
handle_function_pointer_reference(bfd *abfd, asection *sec, unsigned int r_type,
                                  struct bfd_link_info *info, 
                                  struct elf_link_hash_entry *h,
                                  bool *func_pointer_ref)
{
  if ((sec->flags & SEC_READONLY) == 0
      && (r_type == R_X86_64_64
          || (!ABI_64_P (abfd) && is_32bit_relocation(r_type))))
    *func_pointer_ref = true;

  if (!*func_pointer_ref || (bfd_link_pde (info) && h->type == STT_GNU_IFUNC))
    h->pointer_equality_needed = 1;
}

static bool
check_protected_function_reference(struct elf_x86_link_hash_table *htab,
                                   bfd *abfd, struct elf_link_hash_entry *h,
                                   struct elf_x86_link_hash_entry *eh)
{
  if (htab->elf.target_os != is_solaris
      && h->pointer_equality_needed
      && h->type == STT_FUNC
      && eh->def_protected
      && !SYMBOL_DEFINED_NON_SHARED_P (h)
      && h->def_dynamic)
    {
      _bfd_error_handler
        (_("%pB: non-canonical reference to canonical "
           "protected function `%s' in %pB"),
         abfd, h->root.root.string,
         h->root.u.def.section->owner);
      bfd_set_error (bfd_error_bad_value);
      return false;
    }
  return true;
}

static void
update_reference_flags(asection *sec, struct elf_link_hash_entry *h,
                      struct elf_x86_link_hash_entry *eh)
{
  h->non_got_ref = 1;
  
  if (!elf_has_indirect_extern_access (sec->owner))
    eh->non_got_ref_without_indirect_extern_access = 1;

  if (!h->def_regular || (sec->flags & (SEC_CODE | SEC_READONLY)) != 0)
    h->plt.refcount = 1;
}

static struct elf_dyn_relocs *
allocate_dynrel_entry(struct elf_x86_link_hash_table *htab, 
                     struct elf_dyn_relocs **head, asection *sec)
{
  struct elf_dyn_relocs *p = *head;
  
  if (p == NULL || p->sec != sec)
    {
      size_t amt = sizeof *p;
      p = ((struct elf_dyn_relocs *) bfd_alloc (htab->elf.dynobj, amt));
      if (p == NULL)
        return NULL;
      p->next = *head;
      *head = p;
      p->sec = sec;
      p->count = 0;
      p->pc_count = 0;
    }
  return p;
}

static bool
handle_dynamic_relocation(bfd *abfd, struct elf_x86_link_hash_table *htab,
                         asection *sec, unsigned int r_type, unsigned int r_symndx,
                         struct elf_link_hash_entry *h, bool size_reloc)
{
  struct elf_dyn_relocs *p;
  struct elf_dyn_relocs **head;

  if (h != NULL)
    {
      head = &h->dyn_relocs;
    }
  else
    {
      asection *s;
      void **vpp;
      Elf_Internal_Sym *isym;

      isym = bfd_sym_from_r_symndx (&htab->elf.sym_cache, abfd, r_symndx);
      if (isym == NULL)
        return false;

      s = bfd_section_from_elf_index (abfd, isym->st_shndx);
      if (s == NULL)
        s = sec;

      vpp = &(elf_section_data (s)->local_dynrel);
      head = (struct elf_dyn_relocs **)vpp;
    }

  p = allocate_dynrel_entry(htab, head, sec);
  if (p == NULL)
    return false;

  p->count += 1;
  if (X86_PCREL_TYPE_P (true, r_type) || size_reloc)
    p->pc_count += 1;
    
  return true;
}

#define R_TYPE_TPOFF32 R_X86_64_TPOFF32
#define R_TYPE_TLSLD R_X86_64_TLSLD
#define R_TYPE_TLSDESC_CALL R_X86_64_TLSDESC_CALL
#define R_TYPE_PLT32 R_X86_64_PLT32
#define R_TYPE_PLTOFF64 R_X86_64_PLTOFF64
#define R_TYPE_SIZE32 R_X86_64_SIZE32
#define R_TYPE_SIZE64 R_X86_64_SIZE64
#define R_TYPE_PC32 R_X86_64_PC32
#define R_TYPE_GNU_VTINHERIT R_X86_64_GNU_VTINHERIT
#define R_TYPE_GNU_VTENTRY R_X86_64_GNU_VTENTRY

static bool
process_relocation(bfd *abfd, struct bfd_link_info *info, asection *sec,
                   const Elf_Internal_Rela *rel, struct elf_x86_link_hash_table *htab,
                   Elf_Internal_Shdr *symtab_hdr, bfd_byte *contents,
                   struct elf_link_hash_entry **sym_hashes, bool *converted)
{
  unsigned int r_type = ELF32_R_TYPE (rel->r_info);
  unsigned int r_symndx = htab->r_sym (rel->r_info);
  struct elf_link_hash_entry *h = NULL;
  struct elf_x86_link_hash_entry *eh = NULL;
  Elf_Internal_Sym *isym = NULL;
  bool converted_reloc = false;
  bool no_dynreloc = false;
  bool size_reloc = false;
  
  if (r_type == R_X86_64_NONE)
    return true;

  if (!validate_symbol_index(abfd, r_symndx, symtab_hdr))
    return false;

  if (!validate_relocation(abfd, sec, r_type, rel))
    return false;

  if (r_symndx < symtab_hdr->sh_info)
    {
      isym = bfd_sym_from_r_symndx (&htab->elf.sym_cache, abfd, r_symndx);
      if (isym == NULL)
        return false;
      h = process_local_symbol(htab, abfd, rel, symtab_hdr, isym);
      if (isym != NULL && h == NULL && ELF_ST_TYPE (isym->st_info) == STT_GNU_IFUNC)
        return false;
    }
  else
    {
      h = _bfd_elf_get_link_hash_entry (sym_hashes, r_symndx, symtab_hdr);
    }

  if (!check_x32_relocation(abfd, r_type, symtab_hdr, h, isym))
    return false;

  eh = (struct elf_x86_link_hash_entry *) h;
  
  if (h != NULL)
    h->ref_regular = 1;

  if (is_gotpcrel_relocation(r_type) && (h == NULL || h->type != STT_GNU_IFUNC))
    {
      Elf_Internal_Rela *irel = (Elf_Internal_Rela *) rel;
      if (!elf_x86_64_convert_load_reloc (abfd, sec, contents, &r_type, irel, h,
                                          &converted_reloc, info))
        return false;
      if (converted_reloc)
        *converted = true;
    }

  if (!_bfd_elf_x86_valid_reloc_p (sec, info, htab, rel, h, isym,
                                   symtab_hdr, &no_dynreloc))
    return false;

  if (!elf_x86_64_tls_transition (info, abfd, sec, contents,
                                  symtab_hdr, sym_hashes,
                                  &r_type, GOT_UNKNOWN,
                                  rel, rel + sec->reloc_count, h, isym, false))
    return false;

  if (h == htab->elf.hgot)
    htab->got_referenced = true;

  switch (r_type)
    {
    case R_TYPE_TLSLD:
      htab->tls_ld_or_ldm_got.refcount = 1;
      if (eh != NULL)
        eh->zero_undefweak &= 0x2;
      break;

    case R_TYPE_TPOFF32:
      if (!bfd_link_executable (info) && ABI_64_P (abfd))
        {
          elf_x86_64_need_pic (info, abfd, sec, h, symtab_hdr, isym,
                              &x86_64_elf_howto_table[r_type]);
          return false;
        }
      if (eh != NULL)
        eh->zero_undefweak &= 0x2;
      break;

    case R_TYPE_TLSDESC_CALL:
      htab->has_tls_desc_call = 1;
      if (!handle_got_relocation(abfd, htab, symtab_hdr, r_type, r_symndx, h, eh, isym))
        return false;
      break;

    case R_X86_64_GOTTPOFF:
    case R_X86_64_CODE_4_GOTTPOFF:
    case R_X86_64_CODE_5_GOTTPOFF:
    case R_X86_64_CODE_6_GOTTPOFF:
      if (!bfd_link_executable (info))
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
      if (!handle_got_relocation(abfd, htab, symtab_hdr, r_type, r_symndx, h, eh, isym))
        return false;
    case R_X86_64_GOTOFF64:
    case R_X86_64_GOTPC32:
    case R_X86_64_GOTPC64:
      if (eh != NULL)
        eh->zero_undefweak &= 0x2;
      break;

    case R_TYPE_PLT32:
      if (h == NULL)
        break;
      eh->zero_undefweak &= 0x2;
      h->needs_plt = 1;
      h->plt.refcount = 1;
      break;

    case R_TYPE_PLTOFF64:
      if (h != NULL)
        {
          h->needs_plt = 1;
          h->plt.refcount = 1;
        }
      if (eh != NULL)
        eh->zero_undefweak &= 0x2;
      break;

    case R_TYPE_SIZE32:
    case R_TYPE_SIZE64:
      size_reloc = true;
      goto handle_dynrel;

    case R_X86_64_32:
      if (!ABI_64_P (abfd))
        goto pointer_reloc;
    case R_X86_64_8:
    case R_X86_64_16:
    case R_X86_64_32S:
      if (needs_overflow_check(htab, info, sec, h, converted_reloc))
        {
          elf_x86_64_need_pic (info, abfd, sec, h, symtab_hdr, isym,
                              &x86_64_elf_howto_table[r_type]);
          return false;
        }

    case R_X86_64_PC8:
    case R_X86_64_PC16:
    case R_TYPE_PC32:
    case R_X86_64_PC64:
    case R_X86_64_64:
    pointer_reloc:
      if (eh != NULL && (sec->flags & SEC_CODE) != 0)
        eh->zero_undefweak |= 0x2;
        
      if (h != NULL && (bfd_link_executable (info) || h->type == STT_GNU_IFUNC))
        {
          bool func_pointer_ref = false;

          if (r_type == R_TYPE_PC32)
            handle_pc32_relocation(sec, info, h);
          else if (r_type != R_X86_64_PC64)
            handle_function_pointer_reference(abfd, sec, r_type, info, h, &func_pointer_ref);

          if (!func_pointer_ref)
            {
              update_reference_flags(sec, h, eh);
              if (!check_protected_function_reference(htab, abfd, h, eh))
                return false;
            }
        }

    handle_dynrel:
      if (!no_dynreloc
          && NEED_DYNAMIC_RELOCATION_P (true, info, true, h, sec,
                                        r_type, htab->pointer_r_type))
        {
          if (!handle_dynamic_relocation(abfd, htab, sec, r_type, r_symndx, h, size_reloc))
            return false;
        }
      break;

    case R_X86_64_CODE_5_GOTPC32_TLSDESC:
    case R_X86_64_CODE_6_GOTPC32_TLSDESC:
      {
        const char *name = get_symbol_name(abfd, symtab_hdr, h, isym);
        _bfd_error_handler
          (_("%pB: unsupported relocation %s against symbol `%s'"),
           abfd, x86_64_elf_howto_table[r_type].name, name);
      }
      break;

    case R_TYPE_GNU_VTINHERIT:
      if (!bfd_elf_gc_record_vtinherit (abfd, sec, h, rel->r_offset))
        return false;
      break;

    case R_TYPE_GNU_VTENTRY:
      if (!bfd_elf_gc_record_vtentry (abfd, sec, h, rel->r_addend))
        return false;
      break;

    default:
      break;
    }
    
  return true;
}

static bool
elf_x86_64_scan_relocs (bfd *abfd, struct bfd_link_info *info,
                       asection *sec,
                       const Elf_Internal_Rela *relocs)
{
  struct elf_x86_link_hash_table *htab;
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  const Elf_Internal_Rela *rel;
  const Elf_Internal_Rela *rel_end;
  bfd_byte *contents;
  bool converted;

  if (bfd_link_relocatable (info))
    return true;

  htab = elf_x86_hash_table (info, X86_64_ELF_DATA);
  if (htab == NULL)
    {
      sec->check_relocs_failed = 1;
      return false;
    }

  BFD_ASSERT (is_x86_elf (abfd, htab));

  if (elf_section_data (sec)->this_hdr.contents != NULL)
    contents = elf_section_data (sec)->this_hdr.contents;
  else if (!_bfd_elf_mmap_section_contents (abfd, sec, &contents))
    {
      sec->check_relocs_failed = 1;
      return false;
    }

  symtab_hdr = &elf_symtab_hdr (abfd);
  sym_hashes = elf_sym_hashes (abfd);
  converted = false;

  rel_end = relocs + sec->reloc_count;
  for (rel = relocs; rel < rel_end; rel++)
    {
      if (!process_relocation(abfd, info, sec, rel, htab, symtab_hdr,
                             contents, sym_hashes, &converted))
        goto error_return;
    }

  if (elf_section_data (sec)->this_hdr.contents != contents)
    {
      if (!converted)
        _bfd_elf_munmap_section_contents (sec, contents);
      else
        {
          elf_section_data (sec)->this_hdr.contents = contents;
          info->cache_size += sec->size;
        }
    }

  if (elf_section_data (sec)->relocs != relocs && converted)
    elf_section_data (sec)->relocs = (Elf_Internal_Rela *) relocs;

  return true;

 error_return:
  if (elf_section_data (sec)->this_hdr.contents != contents)
    _bfd_elf_munmap_section_contents (sec, contents);
  sec->check_relocs_failed = 1;
  return false;
}

static bool
is_elf_flavour(bfd *abfd)
{
  return bfd_get_flavour(abfd) == bfd_target_elf_flavour;
}

static bool
process_elf_relocations(bfd *abfd, struct bfd_link_info *info)
{
  return _bfd_elf_link_iterate_on_relocs(abfd, info, elf_x86_64_scan_relocs);
}

static bool
scan_input_relocations(struct bfd_link_info *info)
{
  bfd *abfd;
  
  for (abfd = info->input_bfds; abfd != NULL; abfd = abfd->link.next)
  {
    if (!is_elf_flavour(abfd))
      continue;
      
    if (!process_elf_relocations(abfd, info))
      return false;
  }
  
  return true;
}

static bool
elf_x86_64_early_size_sections(bfd *output_bfd, struct bfd_link_info *info)
{
  if (!scan_input_relocations(info))
    return false;
    
  return _bfd_x86_elf_early_size_sections(output_bfd, info);
}

/* Return the relocation value for @tpoff relocation
   if STT_TLS virtual address is ADDRESS.  */

static bfd_vma
elf_x86_64_tpoff (struct bfd_link_info *info, bfd_vma address)
{
  struct elf_link_hash_table *htab = elf_hash_table (info);
  const struct elf_backend_data *bed = get_elf_backend_data (info->output_bfd);
  bfd_vma static_tls_size;

  if (htab->tls_sec == NULL)
    return 0;

  static_tls_size = BFD_ALIGN (htab->tls_size, bed->static_tls_alignment);
  return address - static_tls_size - htab->tls_sec->vma;
}

/* Relocate an x86_64 ELF section.  */

static bool should_skip_relocation(unsigned int r_type, Elf_Internal_Rela **wrel, Elf_Internal_Rela *rel) {
    if (r_type == (int) R_X86_64_GNU_VTINHERIT || r_type == (int) R_X86_64_GNU_VTENTRY) {
        if (*wrel != rel)
            **wrel = *rel;
        return true;
    }
    return false;
}

static bool handle_converted_reloc(unsigned int *r_type, unsigned long r_symndx, 
                                  Elf_Internal_Rela *rel, struct elf_x86_link_hash_table *htab) {
    bool converted_reloc = (*r_type & R_X86_64_converted_reloc_bit) != 0;
    if (converted_reloc) {
        *r_type &= ~R_X86_64_converted_reloc_bit;
        rel->r_info = htab->r_info(r_symndx, *r_type);
    }
    return converted_reloc;
}

static bool handle_discarded_section(asection *sec, Elf_Internal_Rela **wrel, Elf_Internal_Rela *rel,
                                    reloc_howto_type *howto, bfd *input_bfd, asection *input_section,
                                    bfd_byte *contents, struct bfd_link_info *info) {
    if (sec != NULL && discarded_section(sec)) {
        _bfd_clear_contents(howto, input_bfd, input_section, contents, rel->r_offset);
        (*wrel)->r_offset = rel->r_offset;
        (*wrel)->r_info = 0;
        (*wrel)->r_addend = 0;

        if (bfd_link_relocatable(info) && 
            ((input_section->flags & SEC_DEBUGGING) != 0 ||
             elf_section_type(input_section) == SHT_GNU_SFRAME))
            (*wrel)--;
        
        return true;
    }
    return false;
}

static bool handle_relocatable_link(struct bfd_link_info *info, Elf_Internal_Rela **wrel, Elf_Internal_Rela *rel) {
    if (bfd_link_relocatable(info)) {
        if (*wrel != rel)
            **wrel = *rel;
        return true;
    }
    return false;
}

static void handle_x32_zero_addend(unsigned int *r_type, Elf_Internal_Rela *rel, 
                                   bfd_byte *contents, bfd *output_bfd) {
    if (rel->r_addend == 0 && !ABI_64_P(output_bfd)) {
        if (*r_type == R_X86_64_64) {
            *r_type = R_X86_64_32;
            memset(contents + rel->r_offset + 4, 0, 4);
        } else if (*r_type == R_X86_64_SIZE64) {
            *r_type = R_X86_64_SIZE32;
            memset(contents + rel->r_offset + 4, 0, 4);
        }
    }
}

static bool resolve_local_symbol(bfd *output_bfd, Elf_Internal_Sym *sym, asection **sec,
                                Elf_Internal_Rela *rel, struct bfd_link_info *info,
                                struct elf_x86_link_hash_table *htab, bfd *input_bfd,
                                bfd_vma *relocation, bfd_vma *st_size, struct elf_link_hash_entry **h) {
    *relocation = _bfd_elf_rela_local_sym(output_bfd, sym, sec, rel);
    *st_size = sym->st_size;

    if (!bfd_link_relocatable(info) && ELF_ST_TYPE(sym->st_info) == STT_GNU_IFUNC) {
        *h = _bfd_elf_x86_get_local_sym_hash(htab, input_bfd, rel, false);
        if (*h == NULL)
            abort();

        (*h)->root.u.def.value = sym->st_value;
        (*h)->root.u.def.section = *sec;
    }
    return true;
}

static void resolve_global_symbol(struct bfd_link_info *info, bfd *input_bfd,
                                 asection *input_section, Elf_Internal_Rela *rel,
                                 unsigned long r_symndx, Elf_Internal_Shdr *symtab_hdr,
                                 struct elf_link_hash_entry **sym_hashes,
                                 struct elf_link_hash_entry **h, asection **sec,
                                 bfd_vma *relocation, bool *unresolved_reloc,
                                 bfd_vma *st_size) {
    bool warned ATTRIBUTE_UNUSED;
    bool ignored ATTRIBUTE_UNUSED;
    
    RELOC_FOR_GLOBAL_SYMBOL(info, input_bfd, input_section, rel, r_symndx,
                           symtab_hdr, sym_hashes, *h, *sec, *relocation,
                           *unresolved_reloc, warned, ignored);
    *st_size = (*h)->size;
}

#define PLT_ENTRY_SIZE_CONST 16
#define GOT_ENTRY_SIZE 8
#define REX_R 0x04
#define REX_B 0x01
#define REX_W 0x08

static bfd_vma calculate_got_offset(struct elf_link_hash_entry *h,
                                   struct elf_x86_link_hash_table *htab,
                                   asection **base_got, unsigned int plt_entry_size) {
    bfd_vma plt_index;
    
    if (htab->elf.splt != NULL) {
        plt_index = (h->plt.offset / plt_entry_size - htab->plt.has_plt0);
        *base_got = htab->elf.sgotplt;
        return (plt_index + 3) * GOT_ENTRY_SIZE;
    } else {
        plt_index = h->plt.offset / plt_entry_size;
        *base_got = htab->elf.igotplt;
        return plt_index * GOT_ENTRY_SIZE;
    }
}

static bool handle_ifunc_got(struct elf_link_hash_entry *h,
                            struct elf_x86_link_hash_table *htab,
                            bfd *output_bfd, bfd_vma *relocation,
                            unsigned int plt_entry_size, struct bfd_link_info *info) {
    asection *base_got;
    bfd_vma off = h->got.offset;

    if (base_got == NULL)
        abort();

    if (off == (bfd_vma)-1) {
        if (h->plt.offset == (bfd_vma)-1)
            abort();

        off = calculate_got_offset(h, htab, &base_got, plt_entry_size);

        if (h->dynindx == -1 || h->forced_local || info->symbolic) {
            if ((off & 1) != 0)
                off &= ~1;
            else {
                bfd_put_64(output_bfd, *relocation, base_got->contents + off);
                h->got.offset |= 1;
            }
        }
    }

    *relocation = base_got->output_section->vma + base_got->output_offset + off;
    return true;
}

static bool handle_ifunc_plt(struct elf_link_hash_entry *h,
                            struct elf_x86_link_hash_entry *eh,
                            struct elf_x86_link_hash_table *htab,
                            bfd_vma *relocation) {
    asection *resolved_plt;
    bfd_vma plt_offset;

    if (htab->elf.splt != NULL) {
        if (htab->plt_second != NULL) {
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

    *relocation = resolved_plt->output_section->vma + 
                  resolved_plt->output_offset + plt_offset;
    return true;
}

static bool handle_ifunc_dynamic_reloc(bfd *output_bfd, struct bfd_link_info *info,
                                      asection *input_section, Elf_Internal_Rela *rel,
                                      struct elf_link_hash_entry *h, Elf_Internal_Sym *sym,
                                      struct elf_x86_link_hash_table *htab, unsigned int r_type,
                                      Elf_Internal_Shdr *symtab_hdr, bfd *input_bfd) {
    Elf_Internal_Rela outrel;
    asection *sreloc;

    outrel.r_offset = _bfd_elf_section_offset(output_bfd, info, input_section, rel->r_offset);
    if (outrel.r_offset == (bfd_vma)-1 || outrel.r_offset == (bfd_vma)-2)
        abort();

    outrel.r_offset += (input_section->output_section->vma + input_section->output_offset);

    if (POINTER_LOCAL_IFUNC_P(info, h)) {
        info->callbacks->minfo(_("Local IFUNC function `%s' in %pB\n"),
                              h->root.root.string, h->root.u.def.section->owner);
        outrel.r_info = htab->r_info(0, R_X86_64_IRELATIVE);
        outrel.r_addend = (h->root.u.def.value +
                          h->root.u.def.section->output_section->vma +
                          h->root.u.def.section->output_offset);
        
        if (htab->params->report_relative_reloc)
            _bfd_x86_elf_link_report_relative_reloc(info, input_section, h, sym,
                                                   "R_X86_64_IRELATIVE", &outrel);
    } else {
        outrel.r_info = htab->r_info(h->dynindx, r_type);
        outrel.r_addend = 0;
    }

    if (bfd_link_pic(info))
        sreloc = htab->elf.irelifunc;
    else if (htab->elf.splt != NULL)
        sreloc = htab->elf.srelgot;
    else
        sreloc = htab->elf.irelplt;
    
    elf_append_rela(output_bfd, sreloc, &outrel);
    return true;
}

static int
elf_x86_64_relocate_section(bfd *output_bfd, struct bfd_link_info *info,
                           bfd *input_bfd, asection *input_section,
                           bfd_byte *contents, Elf_Internal_Rela *relocs,
                           Elf_Internal_Sym *local_syms, asection **local_sections) {
    struct elf_x86_link_hash_table *htab;
    Elf_Internal_Shdr *symtab_hdr;
    struct elf_link_hash_entry **sym_hashes;
    bfd_vma *local_got_offsets;
    bfd_vma *local_tlsdesc_gotents;
    Elf_Internal_Rela *rel;
    Elf_Internal_Rela *wrel;
    Elf_Internal_Rela *relend;
    unsigned int plt_entry_size;
    bool status;

    if (input_section->check_relocs_failed)
        return false;

    htab = elf_x86_hash_table(info, X86_64_ELF_DATA);
    if (htab == NULL)
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

    status = true;
    rel = wrel = relocs;
    relend = relocs + input_section->reloc_count;

    for (; rel < relend; wrel++, rel++) {
        unsigned int r_type, r_type_tls;
        reloc_howto_type *howto;
        unsigned long r_symndx;
        struct elf_link_hash_entry *h;
        struct elf_x86_link_hash_entry *eh;
        Elf_Internal_Sym *sym;
        asection *sec;
        bfd_vma off, offplt, plt_offset;
        bfd_vma relocation;
        bool unresolved_reloc;
        bfd_reloc_status_type r;
        int tls_type;
        asection *base_got, *resolved_plt;
        bfd_vma st_size;
        bool resolved_to_zero;
        bool relative_reloc;
        bool converted_reloc;
        bool need_copy_reloc_in_pie;
        bool no_copyreloc_p;

        r_type = ELF32_R_TYPE(rel->r_info);
        
        if (should_skip_relocation(r_type, &wrel, rel))
            continue;

        r_symndx = htab->r_sym(rel->r_info);
        converted_reloc = handle_converted_reloc(&r_type, r_symndx, rel, htab);

        howto = elf_x86_64_rtype_to_howto(input_bfd, r_type);
        if (howto == NULL)
            return _bfd_unrecognized_reloc(input_bfd, input_section, r_type);

        h = NULL;
        sym = NULL;
        sec = NULL;
        unresolved_reloc = false;
        
        if (r_symndx < symtab_hdr->sh_info) {
            sym = local_syms + r_symndx;
            sec = local_sections[r_symndx];
            resolve_local_symbol(output_bfd, sym, &sec, rel, info, htab, 
                               input_bfd, &relocation, &st_size, &h);
        } else {
            resolve_global_symbol(info, input_bfd, input_section, rel, r_symndx,
                                symtab_hdr, sym_hashes, &h, &sec, &relocation,
                                &unresolved_reloc, &st_size);
        }

        if (handle_discarded_section(sec, &wrel, rel, howto, input_bfd, 
                                   input_section, contents, info))
            continue;

        if (handle_relocatable_link(info, &wrel, rel))
            continue;

        handle_x32_zero_addend(&r_type, rel, contents, output_bfd);

        eh = (struct elf_x86_link_hash_entry *) h;

        if (h != NULL && h->type == STT_GNU_IFUNC && h->def_regular) {
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
            default:
                break;

            case R_X86_64_GOTPCREL:
            case R_X86_64_GOTPCRELX:
            case R_X86_64_REX_GOTPCRELX:
            case R_X86_64_CODE_4_GOTPCRELX:
            case R_X86_64_CODE_5_GOTPCRELX:
            case R_X86_64_CODE_6_GOTPCRELX:
            case R_X86_64_GOTPCREL64:
                base_got = htab->elf.sgot;
                off = h->got.offset;

                if (base_got == NULL)
                    abort();

                if (off == (bfd_vma) -1) {
                    if (h->plt.offset == (bfd_vma) -1)
                        abort();

                    off = calculate_got_offset(h, htab, &base_got, plt_entry_size);

                    if (h->dynindx == -1 || h->forced_local || info->symbolic) {
                        if ((off & 1) != 0)
                            off &= ~1;
                        else {
                            bfd_put_64(output_bfd, relocation, base_got->contents + off);
                            h->got.offset |= 1;
                        }
                    }
                }

                relocation = base_got->output_section->vma + base_got->output_offset + off;
                goto do_relocation;
            }

            if (h->plt.offset == (bfd_vma) -1) {
                if (r_type == htab->pointer_r_type && (input_section->flags & SEC_CODE) == 0)
                    goto do_ifunc_pointer;
                goto bad_ifunc_reloc;
            }

            handle_ifunc_plt(h, eh, htab, &relocation);

            switch (r_type) {
            default:
            bad_ifunc_reloc:
                if (h->root.root.string)
                    name = h->root.root.string;
                else
                    name = bfd_elf_sym_name(input_bfd, symtab_hdr, sym, NULL);
                _bfd_error_handler(_("%pB: relocation %s against STT_GNU_IFUNC symbol `%s' isn't supported"), 
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
                    if (h->root.root.string)
                        name = h->root.root.string;
                    else
                        name = bfd_elf_sym_name(input_bfd, symtab_hdr, sym, NULL);
                    _bfd_error_handler(_("%pB: relocation %s against STT_GNU_IFUNC symbol `%s' has non-zero addend: %" PRId64),
                                     input_bfd, howto->name, name, (int64_t) rel->r_addend);
                    bfd_set_error(bfd_error_bad_value);
                    return false;
                }

                if ((bfd_link_pic(info) && h->non_got_ref) || h->plt.offset == (bfd_vma) -1) {
                    handle_ifunc_dynamic_reloc(output_bfd, info, input_section, rel,
                                              h, sym, htab, r_type, symtab_hdr, input_bfd);
                    continue;
                }
            case R_X86_64_PC32:
            case R_X86_64_PC64:
            case R_X86_64_PLT32:
                goto do_relocation;
            }
        }

    skip_ifunc:
        resolved_to_zero = (eh != NULL && UNDEFINED_WEAK_RESOLVED_TO_ZERO(info, eh));

        switch (r_type) {
        case R_X86_64_GOT32:
        case R_X86_64_GOT64:
        case R_X86_64_GOTPCREL:
        case R_X86_64_GOTPCRELX:
        case R_X86_64_REX_GOTPCRELX:
        case R_X86_64_CODE_4_GOTPCRELX:
        case R_X86_64_CODE_5_GOTPCRELX:
        case R_X86_64_CODE_6_GOTPCRELX:
        case R_X86_64_GOTPCREL64:
        case R_X86_64_GOTPLT64:
            base_got = htab->elf.sgot;

            if (htab->elf.sgot == NULL)
                abort();

            relative_reloc = false;
            if (h != NULL) {
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
                } else
                    unresolved_reloc = false;
            } else {
                if (local_got_offsets == NULL)
                    abort();

                off = local_got_offsets[r_symndx];

                if ((off & 1) != 0)
                    off &= ~1;
                else {
                    bfd_put_64(output_bfd, relocation, base_got->contents + off);
                    local_got_offsets[r_symndx] |= 1;

                    if (!info->enable_dt_relr && bfd_link_pic(info) &&
                        !(sym->st_shndx == SHN_ABS &&
                          (r_type == R_X86_64_GOTPCREL || r_type == R_X86_64_GOTPCRELX ||
                           r_type == R_X86_64_REX_GOTPCRELX || r_type == R_X86_64_CODE_4_GOTPCRELX ||
                           r_type == R_X86_64_CODE_5_GOTPCRELX || r_type == R_X86_64_CODE_6_GOTPCRELX)))
                        relative_reloc = true;
                }
            }

            if (relative_reloc) {
                asection *s;
                Elf_Internal_Rela outrel;

                s = htab->elf.srelgot;
                if (s == NULL)
                    abort();

                outrel.r_offset = base_got->output_section->vma + base_got->output_offset + off;
                outrel.r_info = htab->r_info(0, R_X86_64_RELATIVE);
                outrel.r_addend = relocation;

                if (htab->params->report_relative_reloc)
                    _bfd_x86_elf_link_report_relative_reloc(info, input_section, h, sym, 
                                                           "R_X86_64_RELATIVE", &outrel);

                elf_append_rela(output_bfd, s, &outrel);
            }

            if (off >= (bfd_vma) -2)
                abort();

            relocation = base_got->output_section->vma + base_got->output_offset + off;
            if (r_type != R_X86_64_GOTPCREL && r_type != R_X86_64_GOTPCRELX &&
                r_type != R_X86_64_REX_GOTPCRELX && r_type != R_X86_64_CODE_4_GOTPCRELX &&
                r_type != R_X86_64_CODE_5_GOTPCRELX && r_type != R_X86_64_CODE_6_GOTPCRELX &&
                r_type != R_X86_64_GOTPCREL64)
                relocation -= htab->elf.sgotplt->output_section->vma - htab->elf.sgotplt->output_offset;
            break;

        case R_X86_64_GOTOFF64:
            if (bfd_link_pic(info) && h) {
                if (!h->def_regular) {
                    const char *v;
                    switch (ELF_ST_VISIBILITY(h->other)) {
                    case STV_HIDDEN:
                        v = _("hidden symbol");
                        break;
                    case STV_INTERNAL:
                        v = _("internal symbol");
                        break;
                    case STV_PROTECTED:
                        v = _("protected symbol");
                        break;
                    default:
                        v = _("symbol");
                        break;
                    }

                    _bfd_error_handler(_("%pB: relocation R_X86_64_GOTOFF64 against undefined %s `%s' can not be used when making a shared object"),
                                     input_bfd, v, h->root.root.string);
                    bfd_set_error(bfd_error_bad_value);
                    return false;
                } else if (!bfd_link_executable(info) && !SYMBOL_REFERENCES_LOCAL_P(info, h) &&
                         (h->type == STT_FUNC || h->type == STT_OBJECT) &&
                         ELF_ST_VISIBILITY(h->other) == STV_PROTECTED) {
                    _bfd_error_handler(_("%pB: relocation R_X86_64_GOTOFF64 against protected %s `%s' can not be used when making a shared object"),
                                     input_bfd, h->type == STT_FUNC ? "function" : "data", h->root.root.string);
                    bfd_set_error(bfd_error_bad_value);
                    return false;
                }
            }

            relocation -= htab->elf.sgotplt->output_section->vma + htab->elf.sgotplt->output_offset;
            break;

        case R_X86_64_GOTPC32:
        case R_X86_64_GOTPC64:
            relocation = htab->elf.sgotplt->output_section->vma + htab->elf.sgotplt->output_offset;
            unresolved_reloc = false;
            break;

        case R_X86_64_PLTOFF64:
            if (h != NULL && (h->plt.offset != (bfd_vma) -1 || eh->plt_got.offset != (bfd_vma) -1) &&
                htab->elf.splt != NULL) {
                if (eh->plt_got.offset != (bfd_vma) -1) {
                    resolved_plt = htab->plt_got;
                    plt_offset = eh->plt_got.offset;
                } else if (htab->plt_second != NULL) {
                    resolved_plt = htab->plt_second;
                    plt_offset = eh->plt_second.offset;
                } else {
                    resolved_plt = htab->elf.splt;
                    plt_offset = h->plt.offset;
                }

                relocation = resolved_plt->output_section->vma + resolved_plt->output_offset + plt_offset;
                unresolved_reloc = false;
            }

            relocation -= htab->elf.sgotplt->output_section->vma + htab->elf.sgotplt->output_offset;
            break;

        case R_X86_64_PLT32:
            if (h == NULL)
                break;

            if ((h->plt.offset == (bfd_vma) -1 && eh->plt_got.offset == (bfd_vma) -1) ||
                htab->elf.splt == NULL)
                break;

        use_plt:
            if (h->plt.offset != (bfd_vma) -1) {
                if (htab->plt_second != NULL) {
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

            relocation = resolved_plt->output_section->vma + resolved_plt->output_offset + plt_offset;
            unresolved_reloc = false;
            break;

        case R_X86_64_SIZE32:
        case R_X86_64_SIZE64:
            relocation = st_size;
            goto direct;

        case R_X86_64_PC8:
        case R_X86_64_PC16:
        case R_X86_64_PC32:
            no_copyreloc_p = (info->nocopyreloc || 
                             (h != NULL && !h->root.linker_def && !h->root.ldscript_def && eh->def_protected));

            if ((input_section->flags & SEC_ALLOC) != 0 &&
                (input_section->flags & SEC_READONLY) != 0 &&
                h != NULL &&
                ((bfd_link_executable(info) &&
                  ((h->root.type == bfd_link_hash_undefweak &&
                    (eh == NULL || !UNDEFINED_WEAK_RESOLVED_TO_ZERO(info, eh))) ||
                   (bfd_link_pie(info) && !SYMBOL_DEFINED_NON_SHARED_P(h) && h->def_dynamic) ||
                   (no_copyreloc_p && h->def_dynamic && !(h->root.u.def.section->flags & SEC_CODE)))) ||
                 (bfd_link_pie(info) && h->root.type == bfd_link_hash_undefweak) ||
                 bf

/* Finish up dynamic symbol handling.  We set the contents of various
   dynamic sections here.  */

static void fill_plt_entry(bfd *output_bfd, struct elf_x86_link_hash_table *htab,
                          asection *plt, bfd_vma plt_offset,
                          asection *gotplt, bfd_vma got_offset)
{
    bfd_vma plt_got_pcrel_offset = (gotplt->output_section->vma
                                    + gotplt->output_offset
                                    + got_offset
                                    - plt->output_section->vma
                                    - plt->output_offset
                                    - plt_offset
                                    - htab->plt.plt_got_insn_size);

    if ((plt_got_pcrel_offset + 0x80000000) > 0xffffffff)
        return;

    bfd_put_32(output_bfd, plt_got_pcrel_offset,
               plt->contents + plt_offset + htab->plt.plt_got_offset);
}

static void setup_plt_sections(struct elf_x86_link_hash_table *htab,
                               asection **plt, asection **gotplt, asection **relplt)
{
    if (htab->elf.splt != NULL) {
        *plt = htab->elf.splt;
        *gotplt = htab->elf.sgotplt;
        *relplt = htab->elf.srelplt;
    } else {
        *plt = htab->elf.iplt;
        *gotplt = htab->elf.igotplt;
        *relplt = htab->elf.irelplt;
    }
}

static bfd_vma calculate_got_offset(struct elf_x86_link_hash_table *htab,
                                    struct elf_link_hash_entry *h, asection *plt)
{
    bfd_vma got_offset;
    
    if (plt == htab->elf.splt) {
        got_offset = (h->plt.offset / htab->plt.plt_entry_size - htab->plt.has_plt0);
        got_offset = (got_offset + 3) * GOT_ENTRY_SIZE;
    } else {
        got_offset = h->plt.offset / htab->plt.plt_entry_size;
        got_offset = got_offset * GOT_ENTRY_SIZE;
    }
    
    return got_offset;
}

static void handle_irelative_reloc(struct bfd_link_info *info,
                                   struct elf_x86_link_hash_table *htab,
                                   struct elf_link_hash_entry *h,
                                   Elf_Internal_Sym *sym,
                                   Elf_Internal_Rela *rela,
                                   asection *relplt,
                                   bfd_vma *plt_index)
{
    if (h->root.u.def.section == NULL)
        return;

    info->callbacks->minfo(_("Local IFUNC function `%s' in %pB\n"),
                          h->root.root.string,
                          h->root.u.def.section->owner);

    rela->r_info = htab->r_info(0, R_X86_64_IRELATIVE);
    rela->r_addend = (h->root.u.def.value
                     + h->root.u.def.section->output_section->vma
                     + h->root.u.def.section->output_offset);

    if (htab->params->report_relative_reloc)
        _bfd_x86_elf_link_report_relative_reloc(info, relplt, h, sym,
                                                "R_X86_64_IRELATIVE", rela);

    *plt_index = htab->next_irelative_index--;
}

static void handle_jump_slot_reloc(struct elf_x86_link_hash_table *htab,
                                   struct elf_link_hash_entry *h,
                                   Elf_Internal_Rela *rela,
                                   asection *resolved_plt,
                                   bfd_vma plt_offset,
                                   bfd_vma *plt_index)
{
    rela->r_info = htab->r_info(h->dynindx, R_X86_64_JUMP_SLOT);
    
    if (htab->params->mark_plt)
        rela->r_addend = (resolved_plt->output_section->vma
                         + plt_offset
                         + htab->plt.plt_indirect_branch_offset);
    else
        rela->r_addend = 0;
    
    *plt_index = htab->next_jump_slot_index++;
}

static void fill_plt0_slots(bfd *output_bfd, struct bfd_link_info *info,
                           struct elf_x86_link_hash_table *htab,
                           struct elf_link_hash_entry *h,
                           asection *plt, bfd_vma plt_index)
{
    if (plt != htab->elf.splt || !htab->plt.has_plt0)
        return;

    bfd_vma plt0_offset = h->plt.offset + htab->lazy_plt->plt_plt_insn_end;

    bfd_put_32(output_bfd, plt_index,
               plt->contents + h->plt.offset + htab->lazy_plt->plt_reloc_offset);

    if (plt0_offset > 0x80000000)
        info->callbacks->fatal(_("%pB: branch displacement overflow in PLT entry for `%s'\n"),
                              output_bfd, h->root.root.string);

    bfd_put_32(output_bfd, -plt0_offset,
               plt->contents + h->plt.offset + htab->lazy_plt->plt_plt_offset);
}

static bool process_plt_entry(bfd *output_bfd, struct bfd_link_info *info,
                              struct elf_x86_link_hash_table *htab,
                              struct elf_link_hash_entry *h,
                              struct elf_x86_link_hash_entry *eh,
                              Elf_Internal_Sym *sym,
                              bool local_undefweak,
                              bool use_plt_second)
{
    bfd_vma plt_index, got_offset, plt_offset;
    Elf_Internal_Rela rela;
    bfd_byte *loc;
    asection *plt, *gotplt, *relplt, *resolved_plt;
    const struct elf_backend_data *bed;
    bfd_vma plt_got_pcrel_offset;

    setup_plt_sections(htab, &plt, &gotplt, &relplt);
    
    VERIFY_PLT_ENTRY(info, h, plt, gotplt, relplt, local_undefweak)

    got_offset = calculate_got_offset(htab, h, plt);

    memcpy(plt->contents + h->plt.offset, htab->plt.plt_entry,
           htab->plt.plt_entry_size);

    if (use_plt_second) {
        memcpy(htab->plt_second->contents + eh->plt_second.offset,
               htab->non_lazy_plt->plt_entry,
               htab->non_lazy_plt->plt_entry_size);
        resolved_plt = htab->plt_second;
        plt_offset = eh->plt_second.offset;
    } else {
        resolved_plt = plt;
        plt_offset = h->plt.offset;
    }

    plt_got_pcrel_offset = (gotplt->output_section->vma
                           + gotplt->output_offset
                           + got_offset
                           - resolved_plt->output_section->vma
                           - resolved_plt->output_offset
                           - plt_offset
                           - htab->plt.plt_got_insn_size);

    if ((plt_got_pcrel_offset + 0x80000000) > 0xffffffff)
        info->callbacks->fatal(_("%pB: PC-relative offset overflow in PLT entry for `%s'\n"),
                              output_bfd, h->root.root.string);

    bfd_put_32(output_bfd, plt_got_pcrel_offset,
               resolved_plt->contents + plt_offset + htab->plt.plt_got_offset);

    if (!local_undefweak) {
        if (htab->plt.has_plt0)
            bfd_put_64(output_bfd, (plt->output_section->vma
                                   + plt->output_offset
                                   + h->plt.offset
                                   + htab->lazy_plt->plt_lazy_offset),
                      gotplt->contents + got_offset);

        rela.r_offset = (gotplt->output_section->vma
                        + gotplt->output_offset
                        + got_offset);

        if (PLT_LOCAL_IFUNC_P(info, h))
            handle_irelative_reloc(info, htab, h, sym, &rela, relplt, &plt_index);
        else
            handle_jump_slot_reloc(htab, h, &rela, resolved_plt, plt_offset, &plt_index);

        fill_plt0_slots(output_bfd, info, htab, h, plt, plt_index);

        bed = get_elf_backend_data(output_bfd);
        loc = relplt->contents + plt_index * bed->s->sizeof_rela;
        bed->s->swap_reloca_out(output_bfd, &rela, loc);
    }

    return true;
}

static bool process_plt_got_entry(bfd *output_bfd, struct bfd_link_info *info,
                                  struct elf_x86_link_hash_table *htab,
                                  struct elf_link_hash_entry *h,
                                  struct elf_x86_link_hash_entry *eh)
{
    bfd_vma got_offset, plt_offset;
    asection *plt, *got;
    bool got_after_plt;
    int32_t got_pcrel_offset;

    plt = htab->plt_got;
    got = htab->elf.sgot;
    got_offset = h->got.offset;

    if (got_offset == (bfd_vma)-1
        || (h->type == STT_GNU_IFUNC && h->def_regular)
        || plt == NULL
        || got == NULL)
        abort();

    plt_offset = eh->plt_got.offset;
    memcpy(plt->contents + plt_offset,
           htab->non_lazy_plt->plt_entry,
           htab->non_lazy_plt->plt_entry_size);

    got_pcrel_offset = (got->output_section->vma
                       + got->output_offset
                       + got_offset
                       - plt->output_section->vma
                       - plt->output_offset
                       - plt_offset
                       - htab->non_lazy_plt->plt_got_insn_size);

    got_after_plt = got->output_section->vma > plt->output_section->vma;
    if ((got_after_plt && got_pcrel_offset < 0)
        || (!got_after_plt && got_pcrel_offset > 0))
        info->callbacks->fatal(_("%pB: PC-relative offset overflow in GOT PLT entry for `%s'\n"),
                              output_bfd, h->root.root.string);

    bfd_put_32(output_bfd, got_pcrel_offset,
               plt->contents + plt_offset + htab->non_lazy_plt->plt_got_offset);

    return true;
}

static bool handle_ifunc_got_entry(bfd *output_bfd, struct bfd_link_info *info,
                                   struct elf_x86_link_hash_table *htab,
                                   struct elf_link_hash_entry *h,
                                   struct elf_x86_link_hash_entry *eh,
                                   Elf_Internal_Sym *sym,
                                   Elf_Internal_Rela *rela,
                                   asection **relgot,
                                   const char **relative_reloc_name)
{
    if (h->plt.offset == (bfd_vma)-1) {
        if (htab->elf.splt == NULL)
            *relgot = htab->elf.irelplt;
        
        if (SYMBOL_REFERENCES_LOCAL_P(info, h)) {
            if (h->root.u.def.section == NULL)
                return false;

            info->callbacks->minfo(_("Local IFUNC function `%s' in %pB\n"),
                                  h->root.root.string,
                                  h->root.u.def.section->owner);

            rela->r_info = htab->r_info(0, R_X86_64_IRELATIVE);
            rela->r_addend = (h->root.u.def.value
                            + h->root.u.def.section->output_section->vma
                            + h->root.u.def.section->output_offset);
            *relative_reloc_name = "R_X86_64_IRELATIVE";
            return true;
        }
        return false;
    }
    
    if (!bfd_link_pic(info)) {
        asection *plt;
        bfd_vma plt_offset;

        if (!h->pointer_equality_needed)
            abort();

        if (htab->plt_second != NULL) {
            plt = htab->plt_second;
            plt_offset = eh->plt_second.offset;
        } else {
            plt = htab->elf.splt ? htab->elf.splt : htab->elf.iplt;
            plt_offset = h->plt.offset;
        }
        
        bfd_put_64(output_bfd, (plt->output_section->vma
                               + plt->output_offset
                               + plt_offset),
                  htab->elf.sgot->contents + h->got.offset);
    }
    
    return !bfd_link_pic(info);
}

static bool process_got_entry(bfd *output_bfd, struct bfd_link_info *info,
                              struct elf_x86_link_hash_table *htab,
                              struct elf_link_hash_entry *h,
                              struct elf_x86_link_hash_entry *eh,
                              Elf_Internal_Sym *sym,
                              bool local_undefweak)
{
    Elf_Internal_Rela rela;
    asection *relgot = htab->elf.srelgot;
    const char *relative_reloc_name = NULL;
    bool generate_dynamic_reloc = true;

    if (htab->elf.sgot == NULL || htab->elf.srelgot == NULL)
        abort();

    rela.r_offset = (htab->elf.sgot->output_section->vma
                    + htab->elf.sgot->output_offset
                    + (h->got.offset & ~(bfd_vma)1));

    if (h->def_regular && h->type == STT_GNU_IFUNC) {
        bool handled = handle_ifunc_got_entry(output_bfd, info, htab, h, eh, sym,
                                              &rela, &relgot, &relative_reloc_name);
        if (handled)
            return true;
        if (relative_reloc_name == NULL)
            goto do_glob_dat;
    } else if (bfd_link_pic(info) && SYMBOL_REFERENCES_LOCAL_P(info, h)) {
        if (!SYMBOL_DEFINED_NON_SHARED_P(h))
            return false;
        
        BFD_ASSERT((h->got.offset & 1) != 0);
        
        if (info->enable_dt_relr) {
            generate_dynamic_reloc = false;
        } else {
            rela.r_info = htab->r_info(0, R_X86_64_RELATIVE);
            rela.r_addend = (h->root.u.def.value
                           + h->root.u.def.section->output_section->vma
                           + h->root.u.def.section->output_offset);
            relative_reloc_name = "R_X86_64_RELATIVE";
        }
    } else {
        BFD_ASSERT((h->got.offset & 1) == 0);
do_glob_dat:
        bfd_put_64(output_bfd, (bfd_vma)0,
                  htab->elf.sgot->contents + h->got.offset);
        rela.r_info = htab->r_info(h->dynindx, R_X86_64_GLOB_DAT);
        rela.r_addend = 0;
    }

    if (generate_dynamic_reloc) {
        if (relgot == NULL || relgot->size == 0) {
            info->callbacks->fatal(_("%pB: Unable to generate dynamic relocs because a suitable section does not exist\n"),
                                  output_bfd);
            return false;
        }

        if (relative_reloc_name != NULL && htab->params->report_relative_reloc)
            _bfd_x86_elf_link_report_relative_reloc(info, relgot, h, sym,
                                                    relative_reloc_name, &rela);

        elf_append_rela(output_bfd, relgot, &rela);
    }

    return true;
}

static bool process_copy_reloc(bfd *output_bfd,
                               struct elf_x86_link_hash_table *htab,
                               struct elf_link_hash_entry *h)
{
    Elf_Internal_Rela rela;
    asection *s;

    VERIFY_COPY_RELOC(h, htab)

    rela.r_offset = (h->root.u.def.value
                    + h->root.u.def.section->output_section->vma
                    + h->root.u.def.section->output_offset);
    rela.r_info = htab->r_info(h->dynindx, R_X86_64_COPY);
    rela.r_addend = 0;
    
    if (h->root.u.def.section == htab->elf.sdynrelro)
        s = htab->elf.sreldynrelro;
    else
        s = htab->elf.srelbss;
    
    elf_append_rela(output_bfd, s, &rela);
    
    return true;
}

static void update_symbol_for_plt(struct elf_link_hash_entry *h,
                                  struct elf_x86_link_hash_entry *eh,
                                  Elf_Internal_Sym *sym,
                                  bool local_undefweak)
{
    if (!local_undefweak && !h->def_regular &&
        (h->plt.offset != (bfd_vma)-1 || eh->plt_got.offset != (bfd_vma)-1)) {
        sym->st_shndx = SHN_UNDEF;
        if (!h->pointer_equality_needed)
            sym->st_value = 0;
    }
}

static bool elf_x86_64_finish_dynamic_symbol(bfd *output_bfd,
                                             struct bfd_link_info *info,
                                             struct elf_link_hash_entry *h,
                                             Elf_Internal_Sym *sym)
{
    struct elf_x86_link_hash_table *htab;
    bool use_plt_second;
    struct elf_x86_link_hash_entry *eh;
    bool local_undefweak;

    htab = elf_x86_hash_table(info, X86_64_ELF_DATA);
    use_plt_second = htab->elf.splt != NULL && htab->plt_second != NULL;
    
    eh = (struct elf_x86_link_hash_entry *)h;
    if (eh->no_finish_dynamic_symbol)
        abort();

    local_undefweak = UNDEFINED_WEAK_RESOLVED_TO_ZERO(info, eh);

    if (h->plt.offset != (bfd_vma)-1) {
        if (!process_plt_entry(output_bfd, info, htab, h, eh, sym,
                              local_undefweak, use_plt_second))
            return false;
    } else if (eh->plt_got.offset != (bfd_vma)-1) {
        if (!process_plt_got_entry(output_bfd, info, htab, h, eh))
            return false;
    }

    update_symbol_for_plt(h, eh, sym, local_undefweak);
    
    _bfd_x86_elf_link_fixup_ifunc_symbol(info, htab, h, sym);

    if (h->got.offset != (bfd_vma)-1 &&
        !GOT_TLS_GD_ANY_P(elf_x86_hash_entry(h)->tls_type) &&
        elf_x86_hash_entry(h)->tls_type != GOT_TLS_IE &&
        !local_undefweak) {
        if (!process_got_entry(output_bfd, info, htab, h, eh, sym, local_undefweak))
            return false;
    }

    if (h->needs_copy) {
        if (!process_copy_reloc(output_bfd, htab, h))
            return false;
    }

    return true;
}

/* Finish up local dynamic symbol handling.  We set the contents of
   various dynamic sections here.  */

static int
elf_x86_64_finish_local_dynamic_symbol (void **slot, void *inf)
{
  struct elf_link_hash_entry *h = (struct elf_link_hash_entry *) *slot;
  struct bfd_link_info *info = (struct bfd_link_info *) inf;

  return elf_x86_64_finish_dynamic_symbol (info->output_bfd, info, h, NULL);
}

/* Finish up undefined weak symbol handling in PIE.  Fill its PLT entry
   here since undefined weak symbol may not be dynamic and may not be
   called for elf_x86_64_finish_dynamic_symbol.  */

static bool
elf_x86_64_pie_finish_undefweak_symbol (struct bfd_hash_entry *bh,
					void *inf)
{
  struct elf_link_hash_entry *h = (struct elf_link_hash_entry *) bh;
  struct bfd_link_info *info = (struct bfd_link_info *) inf;

  if (h->root.type != bfd_link_hash_undefweak
      || h->dynindx != -1)
    return true;

  return elf_x86_64_finish_dynamic_symbol (info->output_bfd,
					   info, h, NULL);
}

/* Used to decide how to sort relocs in an optimal manner for the
   dynamic linker, before writing them out.  */

static enum elf_reloc_type_class
check_ifunc_symbol(bfd *abfd, struct elf_x86_link_hash_table *htab,
                   const Elf_Internal_Rela *rela)
{
  unsigned long r_symndx = htab->r_sym(rela->r_info);
  if (r_symndx == STN_UNDEF)
    return reloc_class_normal;

  const struct elf_backend_data *bed = get_elf_backend_data(abfd);
  Elf_Internal_Sym sym;
  
  if (!bed->s->swap_symbol_in(abfd,
                               (htab->elf.dynsym->contents +
                                r_symndx * bed->s->sizeof_sym),
                               0, &sym))
    abort();

  if (ELF_ST_TYPE(sym.st_info) == STT_GNU_IFUNC)
    return reloc_class_ifunc;
    
  return reloc_class_normal;
}

static enum elf_reloc_type_class
classify_by_reloc_type(const Elf_Internal_Rela *rela)
{
  switch ((int) ELF32_R_TYPE(rela->r_info))
    {
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

static enum elf_reloc_type_class
elf_x86_64_reloc_type_class(const struct bfd_link_info *info,
                            const asection *rel_sec ATTRIBUTE_UNUSED,
                            const Elf_Internal_Rela *rela)
{
  bfd *abfd = info->output_bfd;
  struct elf_x86_link_hash_table *htab =
    elf_x86_hash_table(info, X86_64_ELF_DATA);

  if (htab->elf.dynsym != NULL && htab->elf.dynsym->contents != NULL)
    {
      enum elf_reloc_type_class ifunc_class = 
        check_ifunc_symbol(abfd, htab, rela);
      if (ifunc_class != reloc_class_normal)
        return ifunc_class;
    }

  return classify_by_reloc_type(rela);
}

/* Finish up the dynamic sections.  */

static bool
validate_plt_output_section(struct bfd_link_info *info,
                           struct elf_x86_link_hash_table *htab)
{
    if (bfd_is_abs_section(htab->elf.splt->output_section))
    {
        info->callbacks->fatal(_("%P: discarded output section: `%pA'\n"),
                              htab->elf.splt);
        return false;
    }
    return true;
}

static bfd_vma
calculate_got_offset(struct elf_x86_link_hash_table *htab,
                    bfd_vma got_offset,
                    bfd_vma instruction_offset)
{
    return htab->elf.sgotplt->output_section->vma
           + htab->elf.sgotplt->output_offset
           + got_offset
           - htab->elf.splt->output_section->vma
           - htab->elf.splt->output_offset
           - instruction_offset;
}

static void
fill_plt0_entry(bfd *output_bfd, struct elf_x86_link_hash_table *htab)
{
    #define PUSHQ_GOT8_INSTRUCTION_SIZE 6
    #define GOT_OFFSET_8 8
    #define GOT_OFFSET_16 16
    
    memcpy(htab->elf.splt->contents,
           htab->lazy_plt->plt0_entry,
           htab->lazy_plt->plt0_entry_size);
    
    bfd_put_32(output_bfd,
               calculate_got_offset(htab, GOT_OFFSET_8, PUSHQ_GOT8_INSTRUCTION_SIZE),
               htab->elf.splt->contents + htab->lazy_plt->plt0_got1_offset);
    
    bfd_put_32(output_bfd,
               calculate_got_offset(htab, GOT_OFFSET_16, 
                                   htab->lazy_plt->plt0_got2_insn_end),
               htab->elf.splt->contents + htab->lazy_plt->plt0_got2_offset);
}

static bfd_vma
calculate_tlsdesc_got_offset(struct elf_x86_link_hash_table *htab,
                            bfd_vma base_offset,
                            bfd_vma instruction_end)
{
    return htab->elf.sgot->output_section->vma
           + htab->elf.sgot->output_offset
           + base_offset
           - htab->elf.splt->output_section->vma
           - htab->elf.splt->output_offset
           - htab->elf.tlsdesc_plt
           - instruction_end;
}

static void
fill_tlsdesc_plt_entry(bfd *output_bfd, struct elf_x86_link_hash_table *htab)
{
    #define GOT_OFFSET_8 8
    
    bfd_put_64(output_bfd, (bfd_vma)0,
               htab->elf.sgot->contents + htab->elf.tlsdesc_got);
    
    memcpy(htab->elf.splt->contents + htab->elf.tlsdesc_plt,
           htab->lazy_plt->plt_tlsdesc_entry,
           htab->lazy_plt->plt_tlsdesc_entry_size);
    
    bfd_vma got8_offset = htab->elf.sgotplt->output_section->vma
                         + htab->elf.sgotplt->output_offset
                         + GOT_OFFSET_8
                         - htab->elf.splt->output_section->vma
                         - htab->elf.splt->output_offset
                         - htab->elf.tlsdesc_plt
                         - htab->lazy_plt->plt_tlsdesc_got1_insn_end;
    
    bfd_put_32(output_bfd, got8_offset,
               htab->elf.splt->contents + htab->elf.tlsdesc_plt
               + htab->lazy_plt->plt_tlsdesc_got1_offset);
    
    bfd_vma tdg_offset = calculate_tlsdesc_got_offset(htab,
                                                      htab->elf.tlsdesc_got,
                                                      htab->lazy_plt->plt_tlsdesc_got2_insn_end);
    
    bfd_put_32(output_bfd, tdg_offset,
               htab->elf.splt->contents + htab->elf.tlsdesc_plt
               + htab->lazy_plt->plt_tlsdesc_got2_offset);
}

static bool
process_plt_section(bfd *output_bfd,
                   struct bfd_link_info *info,
                   struct elf_x86_link_hash_table *htab)
{
    if (!htab->elf.splt || htab->elf.splt->size == 0)
        return true;
    
    if (!validate_plt_output_section(info, htab))
        return false;
    
    elf_section_data(htab->elf.splt->output_section)->this_hdr.sh_entsize = 
        htab->plt.plt_entry_size;
    
    if (htab->plt.has_plt0)
        fill_plt0_entry(output_bfd, htab);
    
    if (htab->elf.tlsdesc_plt)
        fill_tlsdesc_plt_entry(output_bfd, htab);
    
    return true;
}

static bool
elf_x86_64_finish_dynamic_sections(bfd *output_bfd,
                                  struct bfd_link_info *info)
{
    struct elf_x86_link_hash_table *htab;
    
    htab = _bfd_x86_elf_finish_dynamic_sections(output_bfd, info);
    if (htab == NULL)
        return false;
    
    if (!htab->elf.dynamic_sections_created)
        return true;
    
    if (!process_plt_section(output_bfd, info, htab))
        return false;
    
    if (bfd_link_pie(info))
        bfd_hash_traverse(&info->hash->table,
                         elf_x86_64_pie_finish_undefweak_symbol,
                         info);
    
    return true;
}

/* Fill PLT/GOT entries and allocate dynamic relocations for local
   STT_GNU_IFUNC symbols, which aren't in the ELF linker hash table.
   It has to be done before elf_link_sort_relocs is called so that
   dynamic relocations are properly sorted.  */

static bool
elf_x86_64_output_arch_local_syms
  (bfd *output_bfd ATTRIBUTE_UNUSED,
   struct bfd_link_info *info,
   void *flaginfo ATTRIBUTE_UNUSED,
   int (*func) (void *, const char *,
		Elf_Internal_Sym *,
		asection *,
		struct elf_link_hash_entry *) ATTRIBUTE_UNUSED)
{
  struct elf_x86_link_hash_table *htab
    = elf_x86_hash_table (info, X86_64_ELF_DATA);
  if (htab == NULL)
    return false;

  htab_traverse (htab->loc_hash_table,
		 elf_x86_64_finish_local_dynamic_symbol,
		 info);

  return true;
}

/* Similar to _bfd_elf_get_synthetic_symtab.  Support PLTs with all
   dynamic relocations.   */

static bool
is_valid_plt_section(asection *plt)
{
  return plt != NULL && plt->size > 0 && (plt->flags & SEC_HAS_CONTENTS) != 0;
}

static bool
match_plt_entry(const bfd_byte *contents, const struct elf_x86_lazy_plt_layout *layout,
                size_t offset1, size_t offset2, size_t len2)
{
  return memcmp(contents, layout->plt0_entry, offset1) == 0 &&
         memcmp(contents + offset2, layout->plt0_entry + offset2, len2) == 0;
}

static bool
check_lazy_ibt_plt(const bfd_byte *plt_contents, 
                   const struct elf_x86_lazy_plt_layout *lazy_ibt_plt)
{
  return memcmp(plt_contents + lazy_ibt_plt->plt_entry_size,
                lazy_ibt_plt->plt_entry,
                lazy_ibt_plt->plt_reloc_offset) == 0;
}

static enum elf_x86_plt_type
detect_lazy_plt_type(const bfd_byte *plt_contents, size_t plt_size,
                     const struct elf_x86_lazy_plt_layout **lazy_plt,
                     const struct elf_x86_lazy_plt_layout *lazy_ibt_plt,
                     const struct elf_x86_lazy_plt_layout *lazy_bnd_plt,
                     const struct elf_x86_lazy_plt_layout *lazy_bnd_ibt_plt)
{
  if (plt_size < ((*lazy_plt)->plt_entry_size + (*lazy_plt)->plt_entry_size))
    return plt_unknown;

  if (match_plt_entry(plt_contents, *lazy_plt, (*lazy_plt)->plt0_got1_offset, 6, 2))
    {
      if (check_lazy_ibt_plt(plt_contents, lazy_ibt_plt))
        {
          *lazy_plt = lazy_ibt_plt;
          return plt_lazy | plt_second;
        }
      return plt_lazy;
    }

  if (lazy_bnd_plt != NULL && 
      match_plt_entry(plt_contents, lazy_bnd_plt, lazy_bnd_plt->plt0_got1_offset, 6, 3))
    {
      if (memcmp(plt_contents + lazy_bnd_ibt_plt->plt_entry_size,
                 lazy_bnd_ibt_plt->plt_entry,
                 lazy_bnd_ibt_plt->plt_reloc_offset) == 0)
        *lazy_plt = lazy_bnd_ibt_plt;
      else
        *lazy_plt = lazy_bnd_plt;
      return plt_lazy | plt_second;
    }

  return plt_unknown;
}

static bool
check_non_lazy_plt(const bfd_byte *plt_contents, size_t plt_size,
                   const struct elf_x86_non_lazy_plt_layout *layout)
{
  return layout != NULL && 
         plt_size >= layout->plt_entry_size &&
         memcmp(plt_contents, layout->plt_entry, layout->plt_got_offset) == 0;
}

static enum elf_x86_plt_type
detect_non_lazy_plt_type(const bfd_byte *plt_contents, size_t plt_size,
                         const struct elf_x86_non_lazy_plt_layout **non_lazy_plt,
                         const struct elf_x86_non_lazy_plt_layout *non_lazy_ibt_plt,
                         const struct elf_x86_non_lazy_plt_layout *non_lazy_bnd_plt,
                         const struct elf_x86_non_lazy_plt_layout *non_lazy_bnd_ibt_plt,
                         enum elf_x86_plt_type current_type)
{
  if (current_type == plt_unknown || current_type == plt_non_lazy)
    {
      if (check_non_lazy_plt(plt_contents, plt_size, *non_lazy_plt))
        return plt_non_lazy;
    }

  if (current_type != plt_unknown && current_type != plt_second)
    return current_type;

  if (check_non_lazy_plt(plt_contents, plt_size, non_lazy_ibt_plt))
    {
      *non_lazy_plt = non_lazy_ibt_plt;
      return plt_second;
    }

  if (non_lazy_bnd_plt == NULL)
    return current_type;

  if (check_non_lazy_plt(plt_contents, plt_size, non_lazy_bnd_plt))
    {
      *non_lazy_plt = non_lazy_bnd_plt;
      return plt_second;
    }

  if (check_non_lazy_plt(plt_contents, plt_size, non_lazy_bnd_ibt_plt))
    {
      *non_lazy_plt = non_lazy_bnd_ibt_plt;
      return plt_second;
    }

  return current_type;
}

static void
setup_plt_layouts(bfd *abfd,
                  const struct elf_x86_lazy_plt_layout **lazy_bnd_plt,
                  const struct elf_x86_non_lazy_plt_layout **non_lazy_bnd_plt,
                  const struct elf_x86_lazy_plt_layout **lazy_bnd_ibt_plt,
                  const struct elf_x86_non_lazy_plt_layout **non_lazy_bnd_ibt_plt)
{
  if (ABI_64_P(abfd))
    {
      *lazy_bnd_ibt_plt = &elf_x86_64_lazy_bnd_ibt_plt;
      *non_lazy_bnd_ibt_plt = &elf_x86_64_non_lazy_bnd_ibt_plt;
      *lazy_bnd_plt = &elf_x86_64_lazy_bnd_plt;
      *non_lazy_bnd_plt = &elf_x86_64_non_lazy_bnd_plt;
    }
  else
    {
      *lazy_bnd_ibt_plt = NULL;
      *non_lazy_bnd_ibt_plt = NULL;
      *lazy_bnd_plt = NULL;
      *non_lazy_bnd_plt = NULL;
    }
}

static void
configure_plt_params(struct elf_x86_plt *plt_entry,
                      const struct elf_x86_lazy_plt_layout *lazy_plt,
                      const struct elf_x86_non_lazy_plt_layout *non_lazy_plt,
                      enum elf_x86_plt_type plt_type)
{
  if ((plt_type & plt_lazy))
    {
      plt_entry->plt_got_offset = lazy_plt->plt_got_offset;
      plt_entry->plt_got_insn_size = lazy_plt->plt_got_insn_size;
      plt_entry->plt_entry_size = lazy_plt->plt_entry_size;
    }
  else
    {
      plt_entry->plt_got_offset = non_lazy_plt->plt_got_offset;
      plt_entry->plt_got_insn_size = non_lazy_plt->plt_got_insn_size;
      plt_entry->plt_entry_size = non_lazy_plt->plt_entry_size;
    }
}

static long
process_plt_section(bfd *abfd, struct elf_x86_plt *plt_entry,
                    const struct elf_x86_lazy_plt_layout *lazy_plt,
                    const struct elf_x86_non_lazy_plt_layout *non_lazy_plt,
                    const struct elf_x86_lazy_plt_layout *lazy_ibt_plt,
                    const struct elf_x86_non_lazy_plt_layout *non_lazy_ibt_plt,
                    const struct elf_x86_lazy_plt_layout *lazy_bnd_plt,
                    const struct elf_x86_non_lazy_plt_layout *non_lazy_bnd_plt,
                    const struct elf_x86_lazy_plt_layout *lazy_bnd_ibt_plt,
                    const struct elf_x86_non_lazy_plt_layout *non_lazy_bnd_ibt_plt)
{
  asection *plt;
  bfd_byte *plt_contents;
  enum elf_x86_plt_type plt_type;
  long n, i;

  plt = bfd_get_section_by_name(abfd, plt_entry->name);
  if (!is_valid_plt_section(plt))
    return 0;

  if (!_bfd_elf_mmap_section_contents(abfd, plt, &plt_contents))
    return 0;

  plt_type = plt_unknown;
  
  if (plt_entry->type == plt_unknown)
    {
      const struct elf_x86_lazy_plt_layout *current_lazy = lazy_plt;
      plt_type = detect_lazy_plt_type(plt_contents, plt->size, &current_lazy,
                                       lazy_ibt_plt, lazy_bnd_plt, lazy_bnd_ibt_plt);
      if (plt_type != plt_unknown)
        lazy_plt = current_lazy;
    }

  const struct elf_x86_non_lazy_plt_layout *current_non_lazy = non_lazy_plt;
  plt_type = detect_non_lazy_plt_type(plt_contents, plt->size, &current_non_lazy,
                                       non_lazy_ibt_plt, non_lazy_bnd_plt,
                                       non_lazy_bnd_ibt_plt, plt_type);
  if (plt_type != plt_unknown)
    non_lazy_plt = current_non_lazy;

  if (plt_type == plt_unknown)
    {
      _bfd_elf_munmap_section_contents(plt, plt_contents);
      return 0;
    }

  plt_entry->sec = plt;
  plt_entry->type = plt_type;
  plt_entry->contents = plt_contents;
  
  configure_plt_params(plt_entry, lazy_plt, non_lazy_plt, plt_type);

  i = (plt_type & plt_lazy) ? 1 : 0;

  if (plt_type == (plt_lazy | plt_second))
    {
      plt_entry->count = 0;
      return 0;
    }

  n = plt->size / plt_entry->plt_entry_size;
  plt_entry->count = n;
  return n - i;
}

static long
elf_x86_64_get_synthetic_symtab (bfd *abfd,
				 long symcount ATTRIBUTE_UNUSED,
				 asymbol **syms ATTRIBUTE_UNUSED,
				 long dynsymcount,
				 asymbol **dynsyms,
				 asymbol **ret)
{
  long count, relsize;
  int j;
  const struct elf_x86_lazy_plt_layout *lazy_plt;
  const struct elf_x86_non_lazy_plt_layout *non_lazy_plt;
  const struct elf_x86_lazy_plt_layout *lazy_bnd_plt;
  const struct elf_x86_non_lazy_plt_layout *non_lazy_bnd_plt;
  const struct elf_x86_lazy_plt_layout *lazy_bnd_ibt_plt;
  const struct elf_x86_non_lazy_plt_layout *non_lazy_bnd_ibt_plt;
  const struct elf_x86_lazy_plt_layout *lazy_ibt_plt;
  const struct elf_x86_non_lazy_plt_layout *non_lazy_ibt_plt;
  struct elf_x86_plt plts[] =
    {
      { ".plt", NULL, NULL, plt_unknown, 0, 0, 0, 0 },
      { ".plt.got", NULL, NULL, plt_non_lazy, 0, 0, 0, 0 },
      { ".plt.sec", NULL, NULL, plt_second, 0, 0, 0, 0 },
      { ".plt.bnd", NULL, NULL, plt_second, 0, 0, 0, 0 },
      { NULL, NULL, NULL, plt_non_lazy, 0, 0, 0, 0 }
    };

  *ret = NULL;

  if ((abfd->flags & (DYNAMIC | EXEC_P)) == 0)
    return 0;

  if (dynsymcount <= 0)
    return 0;

  relsize = bfd_get_dynamic_reloc_upper_bound (abfd);
  if (relsize <= 0)
    return -1;

  lazy_plt = &elf_x86_64_lazy_plt;
  non_lazy_plt = &elf_x86_64_non_lazy_plt;
  lazy_ibt_plt = &elf_x86_64_lazy_ibt_plt;
  non_lazy_ibt_plt = &elf_x86_64_non_lazy_ibt_plt;
  
  setup_plt_layouts(abfd, &lazy_bnd_plt, &non_lazy_bnd_plt,
                    &lazy_bnd_ibt_plt, &non_lazy_bnd_ibt_plt);

  count = 0;
  for (j = 0; plts[j].name != NULL; j++)
    {
      count += process_plt_section(abfd, &plts[j], lazy_plt, non_lazy_plt,
                                    lazy_ibt_plt, non_lazy_ibt_plt,
                                    lazy_bnd_plt, non_lazy_bnd_plt,
                                    lazy_bnd_ibt_plt, non_lazy_bnd_ibt_plt);
    }

  return _bfd_x86_elf_get_synthetic_symtab (abfd, count, relsize,
					    (bfd_vma) 0, plts, dynsyms,
					    ret);
}

/* Handle an x86-64 specific section when reading an object file.  This
   is called when elfcode.h finds a section with an unknown type.  */

static bool
elf_x86_64_section_from_shdr (bfd *abfd, Elf_Internal_Shdr *hdr,
			      const char *name, int shindex)
{
  if (hdr->sh_type != SHT_X86_64_UNWIND)
    return false;

  return _bfd_elf_make_section_from_shdr (abfd, hdr, name, shindex);
}

/* Hook called by the linker routine which adds symbols from an object
   file.  We use it to put SHN_X86_64_LCOMMON items in .lbss, instead
   of .bss.  */

static asection* get_or_create_large_common_section(bfd *abfd)
{
    asection *lcomm = bfd_get_section_by_name(abfd, "LARGE_COMMON");
    if (lcomm != NULL)
        return lcomm;

    lcomm = bfd_make_section_with_flags(abfd,
                                        "LARGE_COMMON",
                                        (SEC_ALLOC | SEC_IS_COMMON | SEC_LINKER_CREATED));
    if (lcomm != NULL)
        elf_section_flags(lcomm) |= SHF_X86_64_LARGE;
    
    return lcomm;
}

static bool
elf_x86_64_add_symbol_hook(bfd *abfd,
                           struct bfd_link_info *info ATTRIBUTE_UNUSED,
                           Elf_Internal_Sym *sym,
                           const char **namep ATTRIBUTE_UNUSED,
                           flagword *flagsp ATTRIBUTE_UNUSED,
                           asection **secp,
                           bfd_vma *valp)
{
    if (sym->st_shndx != SHN_X86_64_LCOMMON)
        return true;

    asection *lcomm = get_or_create_large_common_section(abfd);
    if (lcomm == NULL)
        return false;

    *secp = lcomm;
    *valp = sym->st_size;
    return true;
}


/* Given a BFD section, try to locate the corresponding ELF section
   index.  */

static bool
elf_x86_64_elf_section_from_bfd_section (bfd *abfd ATTRIBUTE_UNUSED,
					 asection *sec, int *index_return)
{
  if (sec == &_bfd_elf_large_com_section)
    {
      *index_return = SHN_X86_64_LCOMMON;
      return true;
    }
  return false;
}

/* Process a symbol.  */

static void
elf_x86_64_symbol_processing (bfd *abfd ATTRIBUTE_UNUSED,
			      asymbol *asym)
{
  elf_symbol_type *elfsym = (elf_symbol_type *) asym;

  if (elfsym->internal_elf_sym.st_shndx == SHN_X86_64_LCOMMON)
    {
      asym->section = &_bfd_elf_large_com_section;
      asym->value = elfsym->internal_elf_sym.st_size;
      asym->flags &= ~BSF_GLOBAL;
    }
}

static bool
elf_x86_64_common_definition (Elf_Internal_Sym *sym)
{
  return (sym->st_shndx == SHN_COMMON
	  || sym->st_shndx == SHN_X86_64_LCOMMON);
}

static unsigned int
elf_x86_64_common_section_index (asection *sec)
{
  if ((elf_section_flags (sec) & SHF_X86_64_LARGE) == 0)
    return SHN_COMMON;
  return SHN_X86_64_LCOMMON;
}

static asection *
elf_x86_64_common_section (asection *sec)
{
  const bool is_large_section = (elf_section_flags (sec) & SHF_X86_64_LARGE) != 0;
  return is_large_section ? &_bfd_elf_large_com_section : bfd_com_section_ptr;
}

static bool is_common_symbol_merge_candidate(struct elf_link_hash_entry *h,
                                             bool newdef,
                                             bool olddef,
                                             asection **psec,
                                             const asection *oldsec)
{
    return !olddef
           && h->root.type == bfd_link_hash_common
           && !newdef
           && bfd_is_com_section(*psec)
           && oldsec != *psec;
}

static void handle_normal_common_symbol(struct elf_link_hash_entry *h,
                                       bfd *oldbfd)
{
    h->root.u.c.p->section = bfd_make_section_old_way(oldbfd, "COMMON");
    h->root.u.c.p->section->flags = SEC_ALLOC;
}

static bool is_large_to_normal_conversion(const Elf_Internal_Sym *sym,
                                         const asection *oldsec)
{
    return sym->st_shndx == SHN_COMMON
           && (elf_section_flags(oldsec) & SHF_X86_64_LARGE) != 0;
}

static bool is_normal_to_large_conversion(const Elf_Internal_Sym *sym,
                                         const asection *oldsec)
{
    return sym->st_shndx == SHN_X86_64_LCOMMON
           && (elf_section_flags(oldsec) & SHF_X86_64_LARGE) == 0;
}

static bool
elf_x86_64_merge_symbol(struct elf_link_hash_entry *h,
                       const Elf_Internal_Sym *sym,
                       asection **psec,
                       bool newdef,
                       bool olddef,
                       bfd *oldbfd,
                       const asection *oldsec)
{
    if (!is_common_symbol_merge_candidate(h, newdef, olddef, psec, oldsec))
        return true;

    if (is_large_to_normal_conversion(sym, oldsec))
        handle_normal_common_symbol(h, oldbfd);
    else if (is_normal_to_large_conversion(sym, oldsec))
        *psec = bfd_com_section_ptr;

    return true;
}

static bool
elf_x86_64_section_flags (const Elf_Internal_Shdr *hdr)
{
  if ((hdr->sh_flags & SHF_X86_64_LARGE) != 0)
    hdr->bfd_section->flags |= SEC_ELF_LARGE;

  return true;
}

static bool
elf_x86_64_fake_sections (bfd *abfd ATTRIBUTE_UNUSED,
			  Elf_Internal_Shdr *hdr, asection *sec)
{
  if (sec->flags & SEC_ELF_LARGE)
    hdr->sh_flags |= SHF_X86_64_LARGE;

  return true;
}

static bool
elf_x86_64_copy_private_section_data (bfd *ibfd, asection *isec,
				      bfd *obfd, asection *osec,
				      struct bfd_link_info *link_info)
{
  if (!_bfd_elf_copy_private_section_data (ibfd, isec, obfd, osec, link_info))
    return false;

  if (link_info == NULL && ibfd != obfd)
    elf_section_flags (osec) &= ~SHF_X86_64_LARGE;

  return true;
}

static int
check_section_needs_segment(bfd *abfd, const char *section_name)
{
  asection *s = bfd_get_section_by_name(abfd, section_name);
  return (s && (s->flags & SEC_LOAD)) ? 1 : 0;
}

static int
elf_x86_64_additional_program_headers(bfd *abfd,
                                      struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  int count = 0;
  
  count += check_section_needs_segment(abfd, ".lrodata");
  count += check_section_needs_segment(abfd, ".ldata");
  
  return count;
}

/* Return TRUE iff relocations for INPUT are compatible with OUTPUT. */

static bool
elf_x86_64_relocs_compatible (const bfd_target *input,
			      const bfd_target *output)
{
  unsigned int input_class = xvec_get_elf_backend_data (input)->s->elfclass;
  unsigned int output_class = xvec_get_elf_backend_data (output)->s->elfclass;
  
  if (input_class != output_class)
    return false;
    
  return _bfd_elf_relocs_compatible (input, output);
}

/* Set up x86-64 GNU properties.  Return the first relocatable ELF input
   with GNU properties if found.  Otherwise, return NULL.  */

static void validate_relocation_bits(void)
{
  if ((int) R_X86_64_standard >= (int) R_X86_64_converted_reloc_bit
      || (int) R_X86_64_max <= (int) R_X86_64_converted_reloc_bit
      || ((int) (R_X86_64_GNU_VTINHERIT | R_X86_64_converted_reloc_bit)
	  != (int) R_X86_64_GNU_VTINHERIT)
      || ((int) (R_X86_64_GNU_VTENTRY | R_X86_64_converted_reloc_bit)
	  != (int) R_X86_64_GNU_VTENTRY))
    abort ();
}

static void setup_plt_tables(struct elf_x86_init_table *init_table)
{
  init_table->lazy_plt = &elf_x86_64_lazy_plt;
  init_table->non_lazy_plt = &elf_x86_64_non_lazy_plt;
  init_table->lazy_ibt_plt = &elf_x86_64_lazy_ibt_plt;
  init_table->non_lazy_ibt_plt = &elf_x86_64_non_lazy_ibt_plt;
}

static void setup_sframe_tables(struct elf_x86_init_table *init_table, bfd *output_bfd)
{
  if (ABI_64_P (output_bfd))
    {
      init_table->sframe_lazy_plt = &elf_x86_64_sframe_plt;
      init_table->sframe_non_lazy_plt = &elf_x86_64_sframe_non_lazy_plt;
      init_table->sframe_lazy_ibt_plt = &elf_x86_64_sframe_ibt_plt;
      init_table->sframe_non_lazy_ibt_plt = &elf_x86_64_sframe_non_lazy_ibt_plt;
    }
  else
    {
      init_table->sframe_lazy_plt = NULL;
      init_table->sframe_non_lazy_plt = NULL;
    }
}

static void setup_relocation_functions(struct elf_x86_init_table *init_table, bfd *output_bfd)
{
  if (ABI_64_P (output_bfd))
    {
      init_table->r_info = elf64_r_info;
      init_table->r_sym = elf64_r_sym;
    }
  else
    {
      init_table->r_info = elf32_r_info;
      init_table->r_sym = elf32_r_sym;
    }
}

static bfd *
elf_x86_64_link_setup_gnu_properties (struct bfd_link_info *info)
{
  struct elf_x86_init_table init_table;
  const struct elf_backend_data *bed;
  struct elf_x86_link_hash_table *htab;

  validate_relocation_bits();

  init_table.plt0_pad_byte = 0x90;

  bed = get_elf_backend_data (info->output_bfd);
  htab = elf_x86_hash_table (info, bed->target_id);
  if (!htab)
    abort ();

  setup_plt_tables(&init_table);
  setup_sframe_tables(&init_table, info->output_bfd);
  setup_relocation_functions(&init_table, info->output_bfd);

  return _bfd_x86_elf_link_setup_gnu_properties (info, &init_table);
}

static void add_dt_relr_version(const char **version, int *index)
{
  version[(*index)++] = "GLIBC_ABI_DT_RELR";
}

static void add_gnu2_tls_version(struct elf_x86_link_hash_table *htab,
                                  const char **version, bool *auto_version, int *index)
{
  if (htab->params->gnu2_tls_version_tag && htab->has_tls_desc_call)
    {
      version[*index] = "GLIBC_ABI_GNU2_TLS";
      if (htab->params->gnu2_tls_version_tag == 2)
        auto_version[*index] = true;
      (*index)++;
    }
}

static int add_mark_plt_version(struct elf_x86_link_hash_table *htab,
                                 const char **version, bool *auto_version, int *index)
{
  if (htab->params->mark_plt)
    {
      int mark_plt = *index;
      auto_version[*index] = true;
      version[*index] = "GLIBC_ABI_DT_X86_64_PLT";
      (*index)++;
      return mark_plt;
    }
  return -1;
}

static void add_fallback_glibc_version(struct elf_find_verdep_info *rinfo)
{
  const char *version[4] = { "GLIBC_2.36", NULL, NULL, NULL };
  bool auto_version[4] = { false, false, false, false };
  _bfd_elf_link_add_glibc_version_dependency(rinfo, version, auto_version);
}

static void elf_x86_64_add_glibc_version_dependency(struct elf_find_verdep_info *rinfo)
{
  int i = 0, mark_plt = -1;
  const char *version[4] = { NULL, NULL, NULL, NULL };
  bool auto_version[4] = { false, false, false, false };
  struct elf_x86_link_hash_table *htab;

  if (rinfo->info->enable_dt_relr)
    add_dt_relr_version(version, &i);

  htab = elf_x86_hash_table(rinfo->info, X86_64_ELF_DATA);
  if (htab != NULL)
    {
      add_gnu2_tls_version(htab, version, auto_version, &i);
      mark_plt = add_mark_plt_version(htab, version, auto_version, &i);
    }

  if (i == 0 || !_bfd_elf_link_add_glibc_version_dependency(rinfo, version, auto_version))
    return;

  if (mark_plt >= 0 && !auto_version[mark_plt])
    add_fallback_glibc_version(rinfo);
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

static bool
elf64_x86_64_copy_solaris_special_section_fields (const bfd *ibfd ATTRIBUTE_UNUSED,
						  bfd *obfd ATTRIBUTE_UNUSED,
						  const Elf_Internal_Shdr *isection ATTRIBUTE_UNUSED,
						  Elf_Internal_Shdr *osection ATTRIBUTE_UNUSED)
{
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
