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
elf_x86_64_rtype_to_howto (bfd *abfd, unsigned r_type)
{
  unsigned i;
  const unsigned R_X86_64_32_VAL = (unsigned) R_X86_64_32;
  const unsigned R_X86_64_GNU_VTINHERIT_VAL = (unsigned) R_X86_64_GNU_VTINHERIT;
  const unsigned R_X86_64_max_VAL = (unsigned) R_X86_64_max;
  const unsigned R_X86_64_standard_VAL = (unsigned) R_X86_64_standard;
  const unsigned R_X86_64_vt_offset_VAL = (unsigned) R_X86_64_vt_offset;

  if (r_type == R_X86_64_32_VAL)
    {
      if (ABI_64_P (abfd))
	    i = r_type;
      else
	    i = ARRAY_SIZE (x86_64_elf_howto_table) - 1;
    }
  else if ((r_type >= R_X86_64_standard_VAL && r_type < R_X86_64_GNU_VTINHERIT_VAL)
           || r_type >= R_X86_64_max_VAL)
    {
      _bfd_error_handler (_("%pB: unsupported relocation type %#x"), abfd, r_type);
      bfd_set_error (bfd_error_bad_value);
      return NULL;
    }
  else if (r_type < R_X86_64_GNU_VTINHERIT_VAL)
    {
      i = r_type;
    }
  else /* r_type >= R_X86_64_GNU_VTINHERIT_VAL && r_type < R_X86_64_max_VAL */
    {
      i = r_type - R_X86_64_vt_offset_VAL;
    }

  BFD_ASSERT (x86_64_elf_howto_table[i].type == r_type);
  return &x86_64_elf_howto_table[i];
}

/* Given a BFD reloc type, return a HOWTO structure.  */
static reloc_howto_type *
elf_x86_64_reloc_type_lookup (bfd *abfd,
			      bfd_reloc_code_real_type code)
{
  unsigned int i;
  const unsigned int num_relocs = sizeof(x86_64_reloc_map) / sizeof(x86_64_reloc_map[0]);

  for (i = 0; i < num_relocs; ++i)
    {
      if (x86_64_reloc_map[i].bfd_reloc_val == code)
	return elf_x86_64_rtype_to_howto (abfd,
					  x86_64_reloc_map[i].elf_reloc_val);
    }
  return NULL;
}

static reloc_howto_type *const x86_64_elf_reloc_32_specific =
  &x86_64_elf_howto_table[ARRAY_SIZE (x86_64_elf_howto_table) - 1];

static reloc_howto_type *
elf_x86_64_reloc_name_lookup (bfd *abfd,
			      const char *r_name)
{
  unsigned int i;

  if (!ABI_64_P (abfd) && strcasecmp (r_name, "R_X86_64_32") == 0)
    {
      BFD_ASSERT (x86_64_elf_reloc_32_specific->type == (unsigned int) R_X86_64_32);
      return x86_64_elf_reloc_32_specific;
    }

  for (i = 0; i < ARRAY_SIZE (x86_64_elf_howto_table); i++)
    if (x86_64_elf_howto_table[i].name != NULL
	&& strcasecmp (x86_64_elf_howto_table[i].name, r_name) == 0)
      return &x86_64_elf_howto_table[i];

  return NULL;
}

/* Given an x86_64 ELF reloc type, fill in an arelent structure.  */

static bool
elf_x86_64_info_to_howto (bfd *abfd, arelent *cache_ptr,
			  Elf_Internal_Rela *dst)
{
  if (cache_ptr == NULL || dst == NULL)
    {
      return false;
    }

  unsigned r_type;

  r_type = ELF32_R_TYPE (dst->r_info);
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
  int pr_pid_offset;
  int pr_reg_offset;
  const int pr_cursig_offset = 12;
  const size_t pr_reg_common_size = 216;

  switch (note->descsz)
    {
      default:
	return false;

      case 296:
	pr_pid_offset = 24;
	pr_reg_offset = 72;
	break;

      case 336:
	pr_pid_offset = 32;
	pr_reg_offset = 112;
	break;
    }

  elf_tdata (abfd)->core->signal = bfd_get_16 (abfd, note->descdata + pr_cursig_offset);
  elf_tdata (abfd)->core->lwpid = bfd_get_32 (abfd, note->descdata + pr_pid_offset);

  return _bfd_elfcore_make_pseudosection (abfd, ".reg",
					  pr_reg_common_size, note->descpos + pr_reg_offset);
}

static bool
elf_x86_64_grok_psinfo (bfd *abfd, Elf_Internal_Note *note)
{
  unsigned int pid_offset;
  unsigned int program_offset;
  unsigned int command_offset;

  switch (note->descsz)
    {
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

  struct elf_core_info *core = elf_tdata (abfd)->core;

  core->pid = bfd_get_32 (abfd, note->descdata + pid_offset);

  core->program = _bfd_elfcore_strndup (abfd, note->descdata + program_offset, 16);
  if (core->program == NULL)
    {
      return false;
    }

  core->command = _bfd_elfcore_strndup (abfd, note->descdata + command_offset, 80);
  if (core->command == NULL)
    {
      return false;
    }

  size_t n = strlen (core->command);
  if (n > 0 && core->command[n - 1] == ' ')
    {
      core->command[n - 1] = '\0';
    }

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
  if (abfd == NULL)
    {
      return false;
    }

  bfd_default_set_arch_mach (abfd, bfd_arch_i386, bfd_mach_x86_64);
  return true;
}

static bool
elf32_x86_64_elf_object_p (bfd *abfd)
{
  if (abfd == NULL) {
    return true;
  }
  bfd_default_set_arch_mach (abfd, bfd_arch_i386, bfd_mach_x64_32);
  return true;
}

/* Return TRUE if the TLS access code sequence support transition
   from R_TYPE.  */

#include "bfd.h"
#include "bfdlink.h"
#include "elf-bfd.h"
#include "elf/x86-64.h"

/* Define constants for instruction byte patterns and masks for clarity and maintainability. */

/* REX Prefixes */
#define X86_REX_PREFIX_MASK 0xF0 /* Mask for REX prefix byte (0x4X) */
#define X86_REX_PREFIX_VAL 0x40  /* Value for REX prefix byte (0x4X) */
#define X86_REX_W 0x48           /* REX.W bit set (operand size 64-bit) */
#define X86_REX_R 0x44           /* REX.R bit set (extension to REG field) */
#define X86_REX_B 0x41           /* REX.B bit set (extension to R/M or SIB base field) */

/* Operand and Address Size Overrides */
#define X86_OP_SIZE_OVERRIDE 0x66  /* Operand size override prefix */
#define X86_ADDR_SIZE_OVERRIDE 0x67 /* Address size override prefix */

/* Common Opcodes */
#define X86_LEA_OPCODE 0x8d     /* Load Effective Address */
#define X86_CALL_REL32 0xe8     /* Call relative, 32-bit displacement */
#define X86_MOV_REG_RM_OPCODE 0x8b /* MOV reg, r/m (typical for loads) */
#define X86_ADD_RM_REG_OPCODE 0x01 /* ADD r/m, reg */
#define X86_ADD_REG_RM_OPCODE 0x03 /* ADD reg, r/m */

/* Indirect Call/Jump Opcodes (FF group) */
#define X86_FF_GROUP_OPCODE 0xff /* Opcode prefix for various indirect calls/jumps */
#define X86_CALL_IND_REG_MODRM 0xd0 /* ModR/M byte for CALL *%reg (e.g., FF D0 for CALL *%rax) */

/* MOVABSQ Instruction */
#define X86_MOV_RAX_IMM64_REX_W 0x48 /* REX.W prefix for MOVABSQ */
#define X86_MOV_RAX_IMM64_OPCODE 0xb8 /* Opcode for MOV RAX, imm64 (part of 0x48 0xb8) */

/* VEX Prefix */
#define X86_VEX_PREFIX_3BYTE 0x62 /* Three-byte VEX prefix */

/* MOVRS Instruction (X32 specific) */
#define X86_MOVRS_PREFIX1 0x0f /* First byte of MOVRS prefix */
#define X86_MOVRS_PREFIX2 0x38 /* Second byte of MOVRS prefix */

/* ModR/M Byte Decoding */
/* For RIP-relative addressing, ModR/M byte has MOD = 00, R/M = 101 */
#define X86_MODRM_RIP_RELATIVE_IMM32 0x3d /* ModR/M byte for LEA (MOD=00, REG=111, R/M=101) */
#define X86_MODRM_RIP_RELATIVE_PATTERN 0x05 /* R/M field value for RIP-relative addressing */
#define X86_MODRM_MOD_RM_MASK 0xC7 /* Mask to isolate MOD (bits 7-6) and R/M (bits 2-0) */
#define X86_MODRM_CALL_IND_ABS_DISP32 0x15 /* ModR/M byte for CALL *[rip+disp32] (MOD=00, REG=001, R/M=101) */

/* Relative relocation type suffixes */
#define R_X86_64_converted_reloc_bit 0x1000

/* Instruction Part Lengths */
#define RIP_RELATIVE_DISPLACEMENT_LEN 4 /* Length of 32-bit RIP-relative displacement */
#define LEA_OPCODE_AND_MODRM_LEN 2      /* Length of LEA opcode (0x8d) + ModR/M byte */

/* Helper function to check the relocation for __tls_get_addr. */
static enum elf_x86_tls_error_type
check_tls_get_addr_relocation (bfd *abfd,
                               struct bfd_link_info *info,
                               Elf_Internal_Shdr *symtab_hdr,
                               struct elf_link_hash_entry **sym_hashes,
                               const Elf_Internal_Rela *rel,
                               bool largepic,
                               bool indirect_call)
{
  unsigned long r_symndx = elf_x86_hash_table (info, X86_64_ELF_DATA)->r_sym (rel[1].r_info);

  if (r_symndx < symtab_hdr->sh_info)
    return elf_x86_tls_error_yes;

  struct elf_link_hash_entry *h = sym_hashes[r_symndx - symtab_hdr->sh_info];
  if (h == NULL || !((struct elf_x86_link_hash_entry *) h)->tls_get_addr)
    return elf_x86_tls_error_yes;

  unsigned int r_type_next = (ELF32_R_TYPE (rel[1].r_info) & ~R_X86_64_converted_reloc_bit);

  if (largepic)
    return (r_type_next == R_X86_64_PLTOFF64)
           ? elf_x86_tls_error_none
           : elf_x86_tls_error_yes;
  else if (indirect_call)
    return ((r_type_next == R_X86_64_GOTPCRELX || r_type_next == R_X86_64_GOTPCREL))
           ? elf_x86_tls_error_none
           : elf_x86_tls_error_yes;
  else
    return ((r_type_next == R_X86_64_PC32 || r_type_next == R_X86_64_PLT32))
           ? elf_x86_tls_error_none
           : elf_x86_tls_error_yes;
}

/* Helper function for TLSGD/TLSLD instruction sequence checks. */
static enum elf_x86_tls_error_type
check_tlsgd_tlsld_sequence (bfd *abfd,
                            asection *sec,
                            bfd_byte *contents,
                            bfd_vma offset,
                            unsigned int r_type,
                            const Elf_Internal_Rela *rel,
                            const Elf_Internal_Rela *relend,
                            bool *largepic_out,
                            bool *indirect_call_out)
{
  *largepic_out = false;
  *indirect_call_out = false;
  bool is_64bit_abi = ABI_64_P (abfd);

  if ((rel + 1) >= relend)
    return elf_x86_tls_error_yes;

  /* The 'offset' for TLSGD/TLSLD relocations points to the displacement
     in the LEA instruction. We need to check bytes before and after it. */
  bfd_byte *lea_disp_ptr = contents + offset;
  bfd_byte *call_inst_ptr = contents + offset + RIP_RELATIVE_DISPLACEMENT_LEN; /* Call starts after LEA disp */

  /* Ensure enough bytes are available for the LEA instruction + displacement. */
  unsigned int min_lea_prefix_len = is_64bit_abi ? (X86_OP_SIZE_OVERRIDE + X86_REX_W) : X86_REX_W;
  min_lea_prefix_len = (min_lea_prefix_len & X86_REX_PREFIX_MASK) == X86_REX_PREFIX_VAL ? 4 : 3;

  if (offset < min_lea_prefix_len || (offset + RIP_RELATIVE_DISPLACEMENT_LEN + 4) > sec->size) /* +4 for a minimal call */
    return elf_x86_tls_error_yes;

  if (r_type == R_X86_64_TLSGD)
    {
      /* Check LEA instruction prefix for TLSGD:
         64bit: 0x66 0x48 0x8d 0x3d  (operand size override, REX.W, LEA, RIP-relative)
         32bit:       0x48 0x8d 0x3d  (REX.W, LEA, RIP-relative) */
      if (is_64bit_abi)
        {
          if (!(lea_disp_ptr[-4] == X86_OP_SIZE_OVERRIDE
                && lea_disp_ptr[-3] == X86_REX_W
                && lea_disp_ptr[-2] == X86_LEA_OPCODE
                && lea_disp_ptr[-1] == X86_MODRM_RIP_RELATIVE_IMM32))
            return elf_x86_tls_error_yes;
        }
      else /* 32bit ABI (x32) */
        {
          if (!(lea_disp_ptr[-3] == X86_REX_W
                && lea_disp_ptr[-2] == X86_LEA_OPCODE
                && lea_disp_ptr[-1] == X86_MODRM_RIP_RELATIVE_IMM32))
            return elf_x86_tls_error_yes;
        }

      /* Check call sequence immediately following the LEA displacement. */
      /* Standard call sequence: 0x66 0x48 (REX.W) + call/jmp instruction */
      if (call_inst_ptr[0] == X86_OP_SIZE_OVERRIDE && call_inst_ptr[1] == X86_REX_W)
        {
          /* 0x66 0x48 0xff 0x15 (call *__tls_get_addr@GOTPCREL) */
          if (call_inst_ptr[2] == X86_FF_GROUP_OPCODE && call_inst_ptr[3] == X86_MODRM_CALL_IND_ABS_DISP32)
            *indirect_call_out = true;
          /* 0x66 0x48 0x67 0xe8 (addr32 call __tls_get_addr@PLT) */
          else if (call_inst_ptr[2] == X86_ADDR_SIZE_OVERRIDE && call_inst_ptr[3] == X86_CALL_REL32)
            *indirect_call_out = false;
          /* 0x66 0x48 0xe8 (call __tls_get_addr@PLT) */
          else if (call_inst_ptr[2] == X86_CALL_REL32)
            *indirect_call_out = false;
          else
            goto check_largepic; /* Fall through to largepic check if not standard */
        }
      else
        {
        check_largepic:
          /* Largepic sequence (64bit only):
             movabsq $__tls_get_addr@pltoff, %rax (10 bytes)
             addq $rX, %rax (3 bytes)
             call *%rax (2 bytes) */
          if (!is_64bit_abi
              || (offset + RIP_RELATIVE_DISPLACEMENT_LEN + 15) > sec->size /* 15 = mov(10) + add(3) + call(2) */
              || memcmp (call_inst_ptr, "\x48\xb8", 2) != 0 /* movabsq %rax, imm64 (REX.W + MOV RAX) */
              || call_inst_ptr[11] != X86_ADD_RM_REG_OPCODE /* addq $rX, %rax (ADD reg, r/m) */
              || call_inst_ptr[13] != X86_FF_GROUP_OPCODE /* call *%rax (FF group opcode) */
              || call_inst_ptr[14] != X86_CALL_IND_REG_MODRM /* ModR/M for call *%rax */
              || !((call_inst_ptr[10] == X86_REX_W && call_inst_ptr[12] == 0xd8) /* addq %rbx/%rcx, %rax (REX.W) */
                   || (call_inst_ptr[10] == (X86_REX_W | X86_REX_R) && call_inst_ptr[12] == 0xf8))) /* addq %r15, %rax (REX.W|REX.R) */
            return elf_x86_tls_error_yes;

          *largepic_out = true;
          *indirect_call_out = true; /* Largepic always uses indirect call via register */
        }
    }
  else /* R_X86_64_TLSLD */
    {
      /* Check LEA instruction prefix for TLSLD:
         0x48 0x8d 0x3d (REX.W, LEA, RIP-relative) */
      if (!(lea_disp_ptr[-3] == X86_REX_W
            && lea_disp_ptr[-2] == X86_LEA_OPCODE
            && lea_disp_ptr[-1] == X86_MODRM_RIP_RELATIVE_IMM32))
        return elf_x86_tls_error_yes;

      /* Check call sequence. */
      /* 0xe8 (call __tls_get_addr@PLT) */
      if (call_inst_ptr[0] == X86_CALL_REL32)
        *indirect_call_out = false;
      /* 0xff 0x15 (call *__tls_get_addr@GOTPCREL) */
      else if (call_inst_ptr[0] == X86_FF_GROUP_OPCODE && call_inst_ptr[1] == X86_MODRM_CALL_IND_ABS_DISP32)
        *indirect_call_out = true;
      /* 0x67 0xe8 (addr32 call __tls_get_addr) */
      else if (call_inst_ptr[0] == X86_ADDR_SIZE_OVERRIDE && call_inst_ptr[1] == X86_CALL_REL32)
        *indirect_call_out = false;
      else
        goto check_largepic; /* Fall through to largepic check if not standard */
        {
        check_largepic:
          /* Largepic sequence (64bit only, same as TLSGD) */
          if (!is_64bit_abi
              || (offset + RIP_RELATIVE_DISPLACEMENT_LEN + 15) > sec->size
              || memcmp (call_inst_ptr, "\x48\xb8", 2) != 0
              || call_inst_ptr[11] != X86_ADD_RM_REG_OPCODE
              || call_inst_ptr[13] != X86_FF_GROUP_OPCODE
              || call_inst_ptr[14] != X86_CALL_IND_REG_MODRM
              || !((call_inst_ptr[10] == X86_REX_W && call_inst_ptr[12] == 0xd8)
                   || (call_inst_ptr[10] == (X86_REX_W | X86_REX_R) && call_inst_ptr[12] == 0xf8)))
            return elf_x86_tls_error_yes;

          *largepic_out = true;
          *indirect_call_out = true;
        }
    }
  return elf_x86_tls_error_none;
}

/* Helper function for GOTTPOFF transition checks. */
static enum elf_x86_tls_error_type
check_gottpoff_transition (bfd *abfd,
                           asection *sec,
                           bfd_byte *contents,
                           bfd_vma offset,
                           unsigned int r_type)
{
  bfd_byte modrm_byte;
  bool is_64bit_abi = ABI_64_P (abfd);
  bfd_byte *disp_ptr = contents + offset; /* Points to the 32-bit displacement */

  /* Ensure there's at least 1 byte (ModR/M) before the displacement and 4 bytes for disp. */
  if (offset < 1 || (offset + RIP_RELATIVE_DISPLACEMENT_LEN) > sec->size)
    return elf_x86_tls_error_yes;

  modrm_byte = disp_ptr[-1]; /* ModR/M byte is before the displacement */

  switch (r_type)
    {
    case R_X86_64_CODE_4_GOTTPOFF:
      /* mov/add foo@gottpoff(%rip), %reg (REX.D5 prefix or X32 MOVRS) */
      if (offset < 4) return elf_x86_tls_error_yes; /* REX + Opcode + ModRM */

      /* X32 MOVRS: 0x0f 0x38 0x8b */
      if (!is_64bit_abi && disp_ptr[-4] == X86_MOVRS_PREFIX1
          && disp_ptr[-3] == X86_MOVRS_PREFIX2 && disp_ptr[-2] == X86_MOV_REG_RM_OPCODE)
        { /* Matched MOVRS */ }
      /* 64bit MOV/ADD with REX.D5 (0xd5 = REX.W|REX.X|REX.B|REX.R) */
      else if (disp_ptr[-4] == 0xd5)
        {
          if (!(disp_ptr[-2] == X86_MOV_REG_RM_OPCODE || disp_ptr[-2] == X86_ADD_REG_RM_OPCODE))
            return elf_x86_tls_error_add_mov;
        }
      else
        return elf_x86_tls_error_yes;
      break;

    case R_X86_64_CODE_5_GOTTPOFF:
      /* movrs foo@gottpoff(%rip), %reg (REX.X|B|R, 0x0f 0x38 0x8b) */
      if (offset < 5) return elf_x86_tls_error_yes; /* REX + 3-byte opcode */

      if ((disp_ptr[-5] & X86_REX_PREFIX_MASK) != X86_REX_PREFIX_VAL /* Check REX prefix */
          || disp_ptr[-4] != X86_MOVRS_PREFIX1
          || disp_ptr[-3] != X86_MOVRS_PREFIX2
          || disp_ptr[-2] != X86_MOV_REG_RM_OPCODE)
        return elf_x86_tls_error_yes;
      break;

    case R_X86_64_CODE_6_GOTTPOFF:
      /* add/movrs foo@gottpoff(%rip), %reg (VEX prefix, 0x62) */
      if (offset < 6) return elf_x86_tls_error_yes; /* VEX + opcode + ModRM */

      if (disp_ptr[-6] != X86_VEX_PREFIX_3BYTE) /* Check VEX prefix */
        return elf_x86_tls_error_yes;

      unsigned int opcode_val = bfd_get_8 (abfd, disp_ptr[-2]);
      if (!(opcode_val == X86_ADD_RM_REG_OPCODE || opcode_val == X86_ADD_REG_RM_OPCODE || opcode_val == X86_MOV_REG_RM_OPCODE))
        return elf_x86_tls_error_add_movrs;
      break;

    case R_X86_64_GOTTPOFF:
      /* mov/add foo@gottpoff(%rip), %reg (standard, with or without REX) */
      if (offset < LEA_OPCODE_AND_MODRM_LEN) return elf_x86_tls_error_yes; /* At least opcode + ModRM */

      bool has_rex_prefix = false;
      if (offset >= LEA_OPCODE_AND_MODRM_LEN + 1) /* Check if there's space for a REX prefix */
        {
          unsigned int rex_byte = bfd_get_8 (abfd, disp_ptr[-3]);
          if ((rex_byte & X86_REX_PREFIX_MASK) == X86_REX_PREFIX_VAL)
            has_rex_prefix = true;
        }

      if (has_rex_prefix)
        {
          if (!(disp_ptr[-2] == X86_MOV_REG_RM_OPCODE || disp_ptr[-2] == X86_ADD_REG_RM_OPCODE))
            return elf_x86_tls_error_add_mov;
        }
      else
        {
          if (is_64bit_abi) return elf_x86_tls_error_yes; /* 64bit ABI *must* have REX */
          if (!(disp_ptr[-2] == X86_MOV_REG_RM_OPCODE || disp_ptr[-2] == X86_ADD_REG_RM_OPCODE))
            return elf_x86_tls_error_add_mov;
        }
      break;

    default:
      return elf_x86_tls_error_yes; /* Should not be reached */
    }

  /* Common ModR/M check for all GOTTPOFF variations:
     RIP-relative addressing (MOD = 00, R/M = 101) */
  return ((modrm_byte & X86_MODRM_MOD_RM_MASK) == X86_MODRM_RIP_RELATIVE_PATTERN)
         ? elf_x86_tls_error_none
         : elf_x86_tls_error_yes;
}

/* Helper function for TLSDESC transition checks. */
static enum elf_x86_tls_error_type
check_tlsdesc_transition (bfd *abfd,
                          asection *sec,
                          bfd_byte *contents,
                          bfd_vma offset,
                          unsigned int r_type)
{
  bfd_byte modrm_byte;
  bool is_64bit_abi = ABI_64_P (abfd);
  bfd_byte *disp_ptr = contents + offset; /* Points to the 32-bit displacement */

  /* Ensure there's at least 1 byte (ModR/M) before the displacement and 4 bytes for disp. */
  if (offset < 1 || (offset + RIP_RELATIVE_DISPLACEMENT_LEN) > sec->size)
    return elf_x86_tls_error_yes;

  modrm_byte = disp_ptr[-1]; /* ModR/M byte is before the displacement */

  /* Check for LEA opcode (common to all TLSDESC cases) */
  if (disp_ptr[-2] != X86_LEA_OPCODE)
    return elf_x86_tls_error_lea;

  switch (r_type)
    {
    case R_X86_64_CODE_4_GOTPC32_TLSDESC:
      /* lea x@tlsdesc(%rip), %reg (reg is r16-r31, REX.D5 prefix) */
      if (offset < 4) return elf_x86_tls_error_yes; /* REX + LEA + ModRM */
      if (disp_ptr[-4] != 0xd5) /* Expected REX.W|X|B|R for lea reg,r/m */
        return elf_x86_tls_error_yes;
      break;

    case R_X86_64_GOTPC32_TLSDESC:
      /* leaq x@tlsdesc(%rip), %rax (LP64) or rex leal x@tlsdesc(%rip), %eax (X32) */
      if (offset < 3) return elf_x86_tls_error_yes; /* REX + LEA + ModRM */

      unsigned int rex_byte = bfd_get_8 (abfd, disp_ptr[-3]);
      unsigned int masked_rex = rex_byte & 0xfb; /* Mask out REX.X bit */

      bool valid_rex_prefix = false;
      if (is_64bit_abi)
        {
          /* For LP64, expected REX.W (0x48) or REX.W|REX.R (0x4C -> 0x48 masked) */
          if (masked_rex == X86_REX_W)
            valid_rex_prefix = true;
        }
      else /* X32 ABI */
        {
          /* For X32, can be REX (0x40) or REX.W (0x48) for compatibility */
          if (masked_rex == X86_REX_W || masked_rex == X86_REX_PREFIX_VAL)
            valid_rex_prefix = true;
        }

      if (!valid_rex_prefix)
        return elf_x86_tls_error_yes;
      break;

    default:
      return elf_x86_tls_error_yes; /* Should not be reached. */
    }

  /* Common ModR/M check for all TLSDESC variations:
     RIP-relative addressing (MOD = 00, R/M = 101) */
  return ((modrm_byte & X86_MODRM_MOD_RM_MASK) == X86_MODRM_RIP_RELATIVE_PATTERN)
         ? elf_x86_tls_error_none
         : elf_x86_tls_error_yes;
}

static enum elf_x86_tls_error_type
elf_x86_64_check_tls_transition (bfd *abfd,
				 struct bfd_link_info *info,
				 asection *sec,
				 bfd_byte *contents,
				 Elf_Internal_Shdr *symtab_hdr,
				 struct elf_link_hash_entry **sym_hashes,
				 unsigned int r_type,
				 const Elf_Internal_Rela *rel,
				 const Elf_Internal_Rela *relend)
{
  bfd_vma offset = rel->r_offset;
  enum elf_x86_tls_error_type ret_val = elf_x86_tls_error_yes;

  switch (r_type)
    {
    case R_X86_64_TLSGD:
    case R_X86_64_TLSLD:
      {
        bool largepic = false;
        bool indirect_call = false;
        ret_val = check_tlsgd_tlsld_sequence (abfd, sec, contents, offset, r_type,
                                              rel, relend, &largepic, &indirect_call);
        if (ret_val != elf_x86_tls_error_none)
          return ret_val;

        return check_tls_get_addr_relocation (abfd, info, symtab_hdr, sym_hashes,
                                              rel, largepic, indirect_call);
      }

    case R_X86_64_CODE_4_GOTTPOFF:
    case R_X86_64_CODE_5_GOTTPOFF:
    case R_X86_64_CODE_6_GOTTPOFF:
    case R_X86_64_GOTTPOFF:
      return check_gottpoff_transition (abfd, sec, contents, offset, r_type);

    case R_X86_64_CODE_4_GOTPC32_TLSDESC:
    case R_X86_64_GOTPC32_TLSDESC:
      return check_tlsdesc_transition (abfd, sec, contents, offset, r_type);

    case R_X86_64_TLSDESC_CALL:
      /* This relocation has already been checked in elf_x86_64_tls_transition
         and explicitly indicates a descriptor call. No further checks needed here. */
      return elf_x86_tls_error_none;

    default:
      /* An unhandled relocation type, which should ideally not reach here if
         called after initial filtering. If it does, it's an internal error.
         `abort()` is used to indicate a severe, unrecoverable internal logic error,
         preserving the original behavior. */
      abort ();
    }
}

/* Return TRUE if the TLS access transition is OK or no transition
   will be performed.  Update R_TYPE if there is a transition.  */

static bool
validate_tlsdesc_call_instruction (bfd *abfd, asection *sec, bfd_vma offset,
                                   const bfd_byte *contents)
{
  if (offset + 2 > sec->size)
    return false;

  const bfd_byte *p = contents + offset;
  unsigned int prefix_len = 0;

  if (!ABI_64_P (abfd))
    {
      if (p[0] == 0x67)
        prefix_len = 1;
      else
        return false;
    }

  if (offset + prefix_len + 2 > sec->size)
    return false;

  if (p[prefix_len] == 0xff && p[1 + prefix_len] == 0x10)
    return true;

  return false;
}

static bool
is_gottpoff_transition (unsigned int from_type, unsigned int to_type)
{
  return (from_type == R_X86_64_CODE_4_GOTTPOFF && to_type == R_X86_64_GOTTPOFF)
      || (from_type == R_X86_64_CODE_5_GOTTPOFF && to_type == R_X86_64_GOTTPOFF)
      || (from_type == R_X86_64_CODE_6_GOTTPOFF && to_type == R_X86_64_GOTTPOFF);
}

static bool
elf_x86_64_tls_transition (struct bfd_link_info *info, bfd *abfd,
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
  unsigned int current_to_type = from_type;
  bool needs_final_check = true;
  unsigned int intermediate_to_type;

  if (h != NULL && (h->type == STT_FUNC || h->type == STT_GNU_IFUNC))
    return true;

  switch (from_type)
    {
    case R_X86_64_TLSDESC_CALL:
      if (!validate_tlsdesc_call_instruction (abfd, sec, rel->r_offset, contents))
	{
	  _bfd_x86_elf_link_report_tls_transition_error
	    (info, abfd, sec, symtab_hdr, h, sym, rel,
	     "R_X86_64_TLSDESC_CALL", NULL,
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
      if (bfd_link_executable (info))
	{
	  if (h == NULL)
	    current_to_type = R_X86_64_TPOFF32;
	  else
	    current_to_type = R_X86_64_GOTTPOFF;
	}

      intermediate_to_type = current_to_type;

      if (from_relocate_section)
	{
	  unsigned int reloc_final_to_type = current_to_type;

	  if (TLS_TRANSITION_IE_TO_LE_P (info, h, tls_type))
	    reloc_final_to_type = R_X86_64_TPOFF32;

	  if (intermediate_to_type == R_X86_64_TLSGD
	      || intermediate_to_type == R_X86_64_GOTPC32_TLSDESC
	      || intermediate_to_type == R_X86_64_CODE_4_GOTPC32_TLSDESC
	      || intermediate_to_type == R_X86_64_TLSDESC_CALL)
	    {
	      if (tls_type == GOT_TLS_IE)
		reloc_final_to_type = R_X86_64_GOTTPOFF;
	    }

	  needs_final_check = (reloc_final_to_type != intermediate_to_type
			       && (from_type == intermediate_to_type
				   || is_gottpoff_transition(from_type, intermediate_to_type)));

	  current_to_type = reloc_final_to_type;
	}
      break;

    case R_X86_64_TLSLD:
      if (bfd_link_executable (info))
	current_to_type = R_X86_64_TPOFF32;
      break;

    default:
      return true;
    }

  if (from_type == current_to_type || is_gottpoff_transition(from_type, current_to_type))
    return true;

  if (needs_final_check)
    {
      enum elf_x86_tls_error_type tls_error =
	elf_x86_64_check_tls_transition (abfd, info, sec, contents,
					 symtab_hdr, sym_hashes,
					 from_type, rel, relend);
      if (tls_error != elf_x86_tls_error_none)
	{
	  const reloc_howto_type *from_howto = &x86_64_elf_howto_table[from_type];
	  const reloc_howto_type *to_howto = &x86_64_elf_howto_table[current_to_type];

	  const char *from_name = (from_howto != NULL ? from_howto->name : "UNKNOWN_FROM_RELOC");
	  const char *to_name = (to_howto != NULL ? to_howto->name : "UNKNOWN_TO_RELOC");

	  _bfd_x86_elf_link_report_tls_transition_error
	    (info, abfd, sec, symtab_hdr, h, sym, rel, from_name,
	     to_name, tls_error);
	  return false;
	}
    }

  *r_type = current_to_type;
  return true;
}

static bool
elf_x86_64_need_pic (struct bfd_link_info *info,
		     bfd *input_bfd, asection *sec,
		     struct elf_link_hash_entry *h,
		     Elf_Internal_Shdr *symtab_hdr,
		     Elf_Internal_Sym *isym,
		     reloc_howto_type *howto)
{
  const char *visibility_str = "";
  const char *undefined_str = "";
  const char *pic_suggestion_str = "";
  const char *object_type_str;
  const char *symbol_name;
  bool symbol_might_need_pic_suggestion = true; // Default assumption

  if (h)
    {
      symbol_name = h->root.root.string;
      switch (ELF_ST_VISIBILITY (h->other))
	{
	case STV_HIDDEN:
	  visibility_str = _("hidden symbol ");
	  symbol_might_need_pic_suggestion = false;
	  break;
	case STV_INTERNAL:
	  visibility_str = _("internal symbol ");
	  symbol_might_need_pic_suggestion = false;
	  break;
	case STV_PROTECTED:
	  visibility_str = _("protected symbol ");
	  symbol_might_need_pic_suggestion = false;
	  break;
	default: /* STV_DEFAULT */
	  // This downcast is assumed to be safe and correct within the BFD context.
	  if (((struct elf_x86_link_hash_entry *) h)->def_protected)
	    visibility_str = _("protected symbol ");
	  else
	    visibility_str = _("symbol ");
	  // symbol_might_need_pic_suggestion remains true for STV_DEFAULT non-protected.
	  break;
	}

      if (!SYMBOL_DEFINED_NON_SHARED_P (h) && !h->def_dynamic)
	undefined_str = _("undefined ");
    }
  else // Symbol not in hash table (e.g., section symbol, local symbol, etc.)
    {
      symbol_name = bfd_elf_sym_name (input_bfd, symtab_hdr, isym, NULL);
      // symbol_might_need_pic_suggestion remains true for these symbols.
    }

  if (bfd_link_dll (info))
    {
      object_type_str = _("a shared object");
      if (symbol_might_need_pic_suggestion)
	pic_suggestion_str = _("; recompile with -fPIC");
    }
  else
    {
      if (bfd_link_pie (info))
	object_type_str = _("a PIE object");
      else
	object_type_str = _("a PDE object"); // Position-Dependent Executable (non-PIE, non-DLL)

      if (symbol_might_need_pic_suggestion)
	pic_suggestion_str = _("; recompile with -fPIE");
    }

  _bfd_error_handler (_("%pB: relocation %s against %s%s`%s' can "
			"not be used when making %s%s"),
		      input_bfd, howto->name, undefined_str, visibility_str, symbol_name,
		      object_type_str, pic_suggestion_str);
  bfd_set_error (bfd_error_bad_value);
  sec->check_relocs_failed = 1;
  return false;
}

/* Move the R bits to the B bits in EVEX payload byte 1.  */
static unsigned int evex_move_r_to_b (unsigned int byte1, bool copy)
{
  const unsigned int B3_MASK = (1u << 5);
  const unsigned int R3_MASK = (1u << 7);

  const unsigned int B4_MASK = (1u << 3);
  const unsigned int R4_MASK = (1u << 4);

  unsigned int r3_shifted_to_b3 = (byte1 & R3_MASK) >> 2;
  unsigned int r4_inverted_shifted_to_b4 = (~byte1 & R4_MASK) >> 1;

  byte1 &= ~(B3_MASK | B4_MASK);

  byte1 |= r3_shifted_to_b3;
  byte1 |= r4_inverted_shifted_to_b4;

  if (!copy) {
    byte1 |= R4_MASK | R3_MASK;
  }

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

#ifndef R_X86_64_GOTPCRELX
#define R_X86_64_GOTPCRELX 17
#endif
#ifndef R_X86_64_REX_GOTPCRELX
#define R_X86_64_REX_GOTPCRELX 47
#endif
#ifndef R_X86_64_CODE_4_GOTPCRELX
#define R_X86_64_CODE_4_GOTPCRELX 50
#endif
#ifndef R_X86_64_CODE_5_GOTPCRELX
#define R_X86_64_CODE_5_GOTPCRELX 51
#endif
#ifndef R_X86_64_CODE_6_GOTPCRELX
#define R_X86_64_CODE_6_GOTPCRELX 52
#endif
#ifndef R_X86_64_PC32
#define R_X86_64_PC32 2
#endif
#ifndef R_X86_64_32S
#define R_X86_64_32S 10
#endif
#ifndef R_X86_64_32
#define R_X86_64_32 1
#endif
#ifndef R_X86_64_converted_reloc_bit
#define R_X86_64_converted_reloc_bit 0x10000000
#endif

#define X86_OPCODE_MOV_R_RM_32        0x8b
#define X86_OPCODE_MOV_IMM_RM_32      0xc7
#define X86_OPCODE_LEA_R_M_32         0x8d
#define X86_OPCODE_TEST_R_RM_32       0x85
#define X86_OPCODE_BINOP_IMM_RM_32    0x81
#define X86_OPCODE_IMUL_IMM_R_RM_32   0x69
#define X86_OPCODE_IMUL_R_RM_32       0xaf
#define X86_OPCODE_CALL_JMP_PUSH_GRP5 0xff
#define X86_OPCODE_JMP_REL32          0xe9
#define X86_OPCODE_CALL_REL32         0xe8
#define X86_OPCODE_PUSH_IMM32         0x68
#define X86_OPCODE_NOP_DEFAULT        0x90

#define X86_PREFIX_REX_MASK           0x4f
#define X86_PREFIX_REX_W              0x08
#define X86_PREFIX_REX_R              0x04
#define X86_PREFIX_REX_X              0x02
#define X86_PREFIX_REX_B              0x01

#define X86_PREFIX_REX2_D5            0xd5
#define X86_PREFIX_EVEX               0x62
#define EVEX_BYTE0_MAP_MASK           0x07
#define EVEX_BYTE0_MAP_4              0x04
#define EVEX_BYTE1_NO_LZ_MASK         0x03
#define EVEX_BYTE2_OPCODE_EXT_MASK    0xe0
#define EVEX_BYTE1_W_BIT              0x80
#define EVEX_BYTE2_NDD_MASK           0x10

#define MODRM_REG_SHIFT               3
#define MODRM_REG_MASK                0x38

#define MODRM_GRP5_CALL_INDIRECT      0x10
#define MODRM_GRP5_JMP_INDIRECT       0x20
#define MODRM_GRP5_PUSH_RM            0x30

#define RIP_RELATIVE_MODRM_BYTE       0x25

#define PC32_ADDEND_VALUE             -4

#ifndef X86_64_ELF_DATA
#define X86_64_ELF_DATA 1
#endif

#define INT32_MAX_POSITIVE_VAL        0x7FFFFFFF
#define UINT32_MAX_VALUE_VAL          0xFFFFFFFF
#define INT32_MIN_NEGATIVE_VAL        0x80000000

#define ADDR_PREFIX_OPCODE_VAL        0x67
#define SEGMENT_OVERRIDE_CS_VAL       0x2e

typedef struct {
  unsigned int opcode;
  unsigned int modrm;
  unsigned char evex[3];
  unsigned int rex;
  unsigned int rex2;
  unsigned int movrs_len;
  bool rex_w;
  bool relocx_type;
} InstructionContext;

static bool
parse_instruction_context (bfd *abfd, bfd_byte *contents, bfd_vma roff,
                           unsigned int current_r_type,
                           InstructionContext *ictx)
{
  unsigned int min_roff_check = 2;
  ictx->movrs_len = 0;
  ictx->rex_w = false;
  ictx->rex = 0;
  ictx->rex2 = 0;
  ictx->relocx_type = false;

  switch (current_r_type)
    {
    case R_X86_64_GOTPCRELX:
      ictx->relocx_type = true;
      break;
    case R_X86_64_REX_GOTPCRELX:
      min_roff_check = 3;
      ictx->relocx_type = true;
      break;
    case R_X86_64_CODE_4_GOTPCRELX:
      min_roff_check = 4;
      ictx->relocx_type = true;
      break;
    case R_X86_64_CODE_5_GOTPCRELX:
      min_roff_check = 5;
      ictx->relocx_type = true;
      break;
    case R_X86_64_CODE_6_GOTPCRELX:
      min_roff_check = 6;
      ictx->relocx_type = true;
      break;
    default:
      return true;
    }

  if (roff < min_roff_check)
    return true;

  ictx->opcode = bfd_get_8 (abfd, contents + roff - 2);
  ictx->modrm = bfd_get_8 (abfd, contents + roff - 1);

  if (ictx->relocx_type)
    {
      switch (current_r_type)
        {
        case R_X86_64_CODE_4_GOTPCRELX:
          {
            unsigned int prev_byte = bfd_get_8 (abfd, contents + roff - 4);
            if (prev_byte == X86_PREFIX_REX2_D5)
              {
                ictx->rex2 = bfd_get_8 (abfd, contents + roff - 3);
                ictx->rex_w = (ictx->rex2 & X86_PREFIX_REX_W) != 0;
              }
            else if (prev_byte == 0x0f)
              {
                if (!(bfd_get_8 (abfd, contents + roff - 3) == 0x38 && bfd_get_8 (abfd, contents + roff - 2) == X86_OPCODE_MOV_R_RM_32))
                  return true;
                ictx->movrs_len = 4;
              }
            else
              return true;
          }
          break;
        case R_X86_64_CODE_5_GOTPCRELX:
          {
            unsigned int rex_byte = bfd_get_8 (abfd, contents + roff - 5);
            if (!((rex_byte | X86_PREFIX_REX_MASK) == X86_PREFIX_REX_MASK
                  && bfd_get_8 (abfd, contents + roff - 4) == 0x0f
                  && bfd_get_8 (abfd, contents + roff - 3) == 0x38
                  && bfd_get_8 (abfd, contents + roff - 2) == X86_OPCODE_MOV_R_RM_32))
              return true;
            ictx->rex = rex_byte;
            ictx->rex_w = (ictx->rex & X86_PREFIX_REX_W) != 0;
            ictx->movrs_len = 5;
          }
          break;
        case R_X86_64_CODE_6_GOTPCRELX:
          {
            if (bfd_get_8 (abfd, contents + roff - 6) != X86_PREFIX_EVEX)
              return true;
            ictx->evex[0] = bfd_get_8 (abfd, contents + roff - 5);
            ictx->evex[1] = bfd_get_8 (abfd, contents + roff - 4);
            ictx->evex[2] = bfd_get_8 (abfd, contents + roff - 3);

            if ((ictx->evex[0] & EVEX_BYTE0_MAP_MASK) != EVEX_BYTE0_MAP_4
                || (ictx->evex[1] & EVEX_BYTE1_NO_LZ_MASK) != 0
                || (ictx->evex[2] & EVEX_BYTE2_OPCODE_EXT_MASK) != 0)
              return true;
            ictx->movrs_len = 6;
            if (!(ictx->evex[0] & 0x80)) ictx->rex2 |= X86_PREFIX_REX_R;
            if (!(ictx->evex[0] & 0x10)) ictx->rex2 |= X86_PREFIX_REX_X;
            if (ictx->evex[1] & EVEX_BYTE1_W_BIT)
              {
                ictx->rex2 |= X86_PREFIX_REX_W;
                ictx->rex_w = true;
              }
          }
          break;
        case R_X86_64_REX_GOTPCRELX:
          ictx->rex = bfd_get_8 (abfd, contents + roff - 3);
          ictx->rex_w = (ictx->rex & X86_PREFIX_REX_W) != 0;
          break;
        default:
          break;
        }
    }
  return false;
}

typedef struct
{
  asection *tsec;
  bfd_vma abs_relocation;
  bool abs_symbol;
  bool local_ref;
  bool special_undef_weak_zero;
} SymbolConversionData;

static bool
resolve_symbol_for_conversion (bfd *abfd, struct bfd_link_info *link_info,
                               struct elf_x86_link_hash_table *htab,
                               unsigned int r_symndx,
                               Elf_Internal_Rela *irel,
                               struct elf_link_hash_entry *h,
                               bool relocx, bool is_branch, bool no_overflow,
                               bool is_pic,
                               SymbolConversionData *sym_data,
                               bfd_vma *out_relocation, bfd_signed_vma *out_raddend,
                               unsigned int opcode)
{
  Elf_Internal_Sym *isym = NULL;

  *out_relocation = 0;
  *out_raddend = irel->r_addend;

  sym_data->tsec = NULL;
  sym_data->abs_relocation = 0;
  sym_data->abs_symbol = false;
  sym_data->local_ref = false;
  sym_data->special_undef_weak_zero = false;

  if (h == NULL)
    {
      isym = bfd_sym_from_r_symndx (&htab->elf.sym_cache, abfd, r_symndx);
      if (isym->st_shndx == SHN_UNDEF)
        return false;

      sym_data->local_ref = true;
      if (isym->st_shndx == SHN_ABS)
        {
          sym_data->tsec = bfd_abs_section_ptr;
          sym_data->abs_symbol = true;
          sym_data->abs_relocation = isym->st_value;
        }
      else if (isym->st_shndx == SHN_COMMON)
        sym_data->tsec = bfd_com_section_ptr;
      else if (isym->st_shndx == SHN_X86_64_LCOMMON)
        sym_data->tsec = &_bfd_elf_large_com_section;
      else
        sym_data->tsec = bfd_section_from_elf_index (abfd, isym->st_shndx);

      Elf_Internal_Rela rel_copy = *irel;
      *out_relocation = _bfd_elf_rela_local_sym (link_info->output_bfd, isym, &sym_data->tsec, &rel_copy);
      *out_raddend = rel_copy.r_addend;
    }
  else
    {
      struct elf_x86_link_hash_entry *eh = elf_x86_hash_entry (h);
      sym_data->abs_symbol = ABS_SYMBOL_P (h);
      sym_data->abs_relocation = h->root.u.def.value;
      sym_data->local_ref = SYMBOL_REFERENCES_LOCAL_P (link_info, h);

      if ((relocx || opcode == X86_OPCODE_MOV_R_RM_32)
          && (h->root.type == bfd_link_hash_undefweak && !eh->linker_def && sym_data->local_ref))
        {
          if (is_branch && no_overflow)
            return false;
          
          bool to_reloc_pc32_temp = (is_branch || !relocx || no_overflow || is_pic);
          if (!is_branch && relocx)
            to_reloc_pc32_temp = false;

          if (to_reloc_pc32_temp && is_pic)
            return false;

          sym_data->special_undef_weak_zero = true;
          *out_relocation = 0;
          *out_raddend = 0;
          return true;
        }
      else if (h->start_stop
               || eh->linker_def
               || ((h->def_regular || h->root.type == bfd_link_hash_defined || h->root.type == bfd_link_hash_defweak)
                   && h != htab->elf.hdynamic && sym_data->local_ref))
        {
          if (no_overflow)
            return false;

          if (h->start_stop)
            sym_data->tsec = h->root.u.def.section;
          else if (h == htab->elf.hehdr_start)
            {
              asection *sec;
              sym_data->tsec = NULL;
              for (sec = link_info->output_bfd->sections; sec != NULL; sec = sec->next)
                if ((sec->flags & SEC_LOAD) != 0 && (sym_data->tsec == NULL || sym_data->tsec->vma > sec->vma))
                  sym_data->tsec = sec;
            }
          else
            sym_data->tsec = h->root.u.def.section;

          if (sym_data->tsec == NULL)
            return false;

          *out_relocation = (h->root.u.def.value + sym_data->tsec->output_section->vma + sym_data->tsec->output_offset);
        }
      else
        return false;
    }

  if (sym_data->tsec != NULL
      && elf_section_data (sym_data->tsec) != NULL
      && (elf_section_flags (sym_data->tsec) & SHF_X86_64_LARGE) != 0)
    return false;

  if (no_overflow && !sym_data->special_undef_weak_zero)
    return false;

  return true;
}


static bool
elf_x86_64_convert_load_reloc (bfd *abfd,
			       asection *input_section,
			       bfd_byte *contents,
			       unsigned int *r_type_p,
			       Elf_Internal_Rela *irel,
			       struct elf_link_hash_entry *h,
			       bool *converted,
			       struct bfd_link_info *link_info)
{
  struct elf_x86_link_hash_table *htab;
  bool is_pic;
  bool no_overflow;
  bool relocx;
  bool is_branch = false;
  unsigned int opcode;
  unsigned int modrm;
  unsigned char evex[3] = { 0, 0, 0 };
  unsigned int current_r_type = *r_type_p;
  unsigned int r_symndx;
  bfd_vma roff = irel->r_offset;
  bfd_vma relocation_val;
  bfd_reloc_status_type r;
  
  InstructionContext inst_ctx;
  SymbolConversionData sym_data;
  bfd_signed_vma current_raddend;

  htab = elf_x86_hash_table (link_info, X86_64_ELF_DATA);
  is_pic = bfd_link_pic (link_info);
  no_overflow = link_info->disable_target_specific_optimizations > 1;

  if (parse_instruction_context (abfd, contents, roff, current_r_type, &inst_ctx))
    return true;

  opcode = inst_ctx.opcode;
  modrm = inst_ctx.modrm;
  evex[0] = inst_ctx.evex[0]; evex[1] = inst_ctx.evex[1]; evex[2] = inst_ctx.evex[2];
  relocx = inst_ctx.relocx_type;

  if (irel->r_addend != PC32_ADDEND_VALUE)
    return true;

  if (opcode == X86_OPCODE_CALL_JMP_PUSH_GRP5)
    {
      switch (modrm & MODRM_REG_MASK)
        {
        case MODRM_GRP5_CALL_INDIRECT:
        case MODRM_GRP5_JMP_INDIRECT:
          is_branch = true;
          break;
        case MODRM_GRP5_PUSH_RM:
          break;
        default:
          return true;
        }
    }

  if (opcode != X86_OPCODE_MOV_R_RM_32 && !relocx)
    return true;

  r_symndx = htab->r_sym (irel->r_info);
  if (!resolve_symbol_for_conversion (abfd, link_info, htab, r_symndx, irel, h,
                                       relocx, is_branch, no_overflow, is_pic,
                                       &sym_data, &relocation_val, &current_raddend,
                                       opcode))
    return true;

  bool to_reloc_pc32_final = (is_branch || !relocx || no_overflow || is_pic);
  if (sym_data.special_undef_weak_zero && !is_branch && relocx)
      to_reloc_pc32_final = false;

  irel->r_addend = current_raddend;

  reloc_howto_type *howto_ptr;
  unsigned int new_r_type = current_r_type;

  if (is_branch)
    {
      new_r_type = R_X86_64_PC32;
      howto_ptr = &x86_64_elf_howto_table[new_r_type];
      r = _bfd_final_link_relocate (howto_ptr, abfd, input_section,
                                    contents, irel->r_offset,
                                    relocation_val, irel->r_addend);
      if (r == bfd_reloc_overflow)
        return true;

      if (modrm == RIP_RELATIVE_MODRM_BYTE)
        {
          bfd_put_8 (abfd, X86_OPCODE_JMP_REL32, contents + roff - 2);
          bfd_put_8 (abfd, X86_OPCODE_NOP_DEFAULT, contents + roff + 2);
          irel->r_offset -= 1;
        }
      else
        {
          struct elf_x86_link_hash_entry *eh = (struct elf_x86_link_hash_entry *) h;
          bfd_put_8 (abfd, X86_OPCODE_CALL_REL32, contents + roff - 2);
          unsigned int nop_byte = htab->params->call_nop_byte;
          bfd_vma nop_offset = irel->r_offset - 2;

          if (eh && eh->tls_get_addr)
            nop_byte = ADDR_PREFIX_OPCODE_VAL;
          else if (htab->params->call_nop_as_suffix)
            {
              nop_offset = irel->r_offset + 2;
            }
          bfd_put_8 (abfd, nop_byte, contents + nop_offset);
          if (nop_offset == irel->r_offset + 2)
              irel->r_offset -= 1;
        }
    }
  else if (current_r_type == R_X86_64_CODE_6_GOTPCRELX && opcode != X86_OPCODE_MOV_R_RM_32)
    {
      if (to_reloc_pc32_final)
        return true;

      bool move_v_r = false;
      unsigned int new_modrm = modrm;
      unsigned int new_opcode = opcode;

      if (opcode == X86_OPCODE_TEST_R_RM_32)
        {
          new_modrm = 0xc0 | ((modrm & MODRM_REG_MASK) >> MODRM_REG_SHIFT);
          new_opcode = 0xf7;
        }
      else if ((opcode | 0x3a) == 0x3b)
        {
          if (!(evex[2] & EVEX_BYTE2_NDD_MASK) && (opcode | 0x38) != 0x3b)
            return true;
          if ((evex[2] & EVEX_BYTE2_NDD_MASK) && (opcode | 0x38) != 0x3b
              && (opcode == 0x19 || opcode == 0x29))
            return true;
          new_modrm = 0xc0 | ((modrm & MODRM_REG_MASK) >> MODRM_REG_SHIFT) | (opcode & 0x38);
          new_opcode = X86_OPCODE_BINOP_IMM_RM_32;
        }
      else if (opcode == X86_OPCODE_IMUL_R_RM_32)
        {
          if (!(evex[2] & EVEX_BYTE2_NDD_MASK))
            new_modrm = 0xc0 | ((modrm & MODRM_REG_MASK) >> MODRM_REG_SHIFT) | (modrm & MODRM_REG_MASK);
          else
            {
              new_modrm = 0xc0 | ((modrm & MODRM_REG_MASK) >> MODRM_REG_SHIFT) | (~evex[1] & MODRM_REG_MASK);
              move_v_r = true;
            }
          new_opcode = X86_OPCODE_IMUL_IMM_R_RM_32;
        }
      else
        return true;

      new_r_type = (evex[1] & EVEX_BYTE1_W_BIT) ? R_X86_64_32S : R_X86_64_32;

      howto_ptr = elf_x86_64_rtype_to_howto (abfd, new_r_type);
      r = _bfd_final_link_relocate (howto_ptr, abfd, input_section,
                                    contents, irel->r_offset,
                                    relocation_val, 0);
      if (r == bfd_reloc_overflow)
        return true;

      if (sym_data.abs_symbol)
        {
          if ((new_r_type == R_X86_64_32S && (relocation_val + INT32_MIN_NEGATIVE_VAL) > UINT32_MAX_VALUE_VAL)
              || (new_r_type == R_X86_64_32 && relocation_val > UINT32_MAX_VALUE_VAL))
            return true;
        }

      bfd_put_8 (abfd, new_opcode, contents + roff - 2);
      bfd_put_8 (abfd, new_modrm, contents + roff - 1);

      evex[0] = evex_move_r_to_b (evex[0], new_opcode == X86_OPCODE_IMUL_IMM_R_RM_32 && !move_v_r);
      if (move_v_r)
        {
          if (!(evex[1] & (1 << 6))) evex[0] &= ~(1 << 7);
          if (!(evex[2] & (1 << 3))) evex[0] &= ~(1 << 4);
          evex[1] |= 0xf << 3;
          evex[2] |= 1 << 3;
          evex[2] &= ~(1 << 4);
          bfd_put_8 (abfd, evex[2], contents + roff - 3);
          bfd_put_8 (abfd, evex[1], contents + roff - 4);
        }
      bfd_put_8 (abfd, evex[0], contents + roff - 5);
      irel->r_addend = 0;
    }
  else
    {
      unsigned int rex_mask_to_clear = X86_PREFIX_REX_R;
      unsigned int rex2_mask_to_clear = X86_PREFIX_REX_R | (X86_PREFIX_REX_X << 4);
      unsigned int new_modrm = modrm;
      unsigned int new_opcode = opcode;

      if (opcode == X86_OPCODE_MOV_R_RM_32)
        {
          if (sym_data.abs_symbol && sym_data.local_ref && relocx)
            to_reloc_pc32_final = false;

          if (to_reloc_pc32_final)
            {
              new_opcode = X86_OPCODE_LEA_R_M_32;
              new_r_type = R_X86_64_PC32;

              howto_ptr = &x86_64_elf_howto_table[new_r_type];
              r = _bfd_final_link_relocate (howto_ptr, abfd, input_section,
                                            contents, irel->r_offset,
                                            relocation_val, irel->r_addend);
              if (r == bfd_reloc_overflow)
                return true;

              if (inst_ctx.movrs_len == 5)
                bfd_put_8 (abfd, inst_ctx.rex, contents + roff - 3);
            }
          else
            {
              new_opcode = X86_OPCODE_MOV_IMM_RM_32;
              new_modrm = 0xc0 | ((modrm & MODRM_REG_MASK) >> MODRM_REG_SHIFT);
              if (inst_ctx.rex_w && ABI_64_P (link_info->output_bfd))
                {
                  new_r_type = R_X86_64_32S;
                }
              else
                {
                  new_r_type = R_X86_64_32;
                  rex_mask_to_clear |= X86_PREFIX_REX_W;
                  rex2_mask_to_clear |= X86_PREFIX_REX_W;
                }
            }
        }
      else
        {
          if (to_reloc_pc32_final)
            return true;

          if (opcode == X86_OPCODE_TEST_R_RM_32 && !(inst_ctx.rex2 & (X86_PREFIX_REX_X << 4)))
            {
              new_modrm = 0xc0 | ((modrm & MODRM_REG_MASK) >> MODRM_REG_SHIFT);
              new_opcode = 0xf7;
            }
          else if ((opcode | 0x38) == 0x3b && !(inst_ctx.rex2 & (X86_PREFIX_REX_X << 4)))
            {
              new_modrm = 0xc0 | ((modrm & MODRM_REG_MASK) >> MODRM_REG_SHIFT) | (opcode & 0x38);
              new_opcode = X86_OPCODE_BINOP_IMM_RM_32;
            }
          else if (opcode == X86_OPCODE_IMUL_R_RM_32 && (inst_ctx.rex2 & (X86_PREFIX_REX_X << 4)))
            {
              new_modrm = 0xc0 | ((modrm & MODRM_REG_MASK) >> MODRM_REG_SHIFT) | (modrm & MODRM_REG_MASK);
              rex_mask_to_clear = 0;
              rex2_mask_to_clear = (X86_PREFIX_REX_X << 4);
              new_opcode = X86_OPCODE_IMUL_IMM_R_RM_32;
            }
          else if (opcode == X86_OPCODE_CALL_JMP_PUSH_GRP5 && !(inst_ctx.rex2 & (X86_PREFIX_REX_X << 4)) && (modrm & MODRM_REG_MASK) == MODRM_GRP5_PUSH_RM)
            {
              bfd_put_8 (abfd, X86_OPCODE_PUSH_IMM32, contents + roff - 1);
              if (inst_ctx.rex) {
                bfd_put_8 (abfd, SEGMENT_OVERRIDE_CS_VAL, contents + roff - 3);
                bfd_put_8 (abfd, inst_ctx.rex, contents + roff - 2);
              } else if (inst_ctx.rex2) {
                bfd_put_8 (abfd, SEGMENT_OVERRIDE_CS_VAL, contents + roff - 4);
                bfd_put_8 (abfd, X86_PREFIX_REX2_D5, contents + roff - 3);
                bfd_put_8 (abfd, inst_ctx.rex2, contents + roff - 2);
              } else {
                bfd_put_8 (abfd, SEGMENT_OVERRIDE_CS_VAL, contents + roff - 2);
              }

              new_r_type = R_X86_64_32S;
              irel->r_addend = 0;
              *r_type_p = new_r_type;
              irel->r_info = htab->r_info (r_symndx, new_r_type | R_X86_64_converted_reloc_bit);
              *converted = true;
              return true;
            }
          else
            return true;

          new_r_type = inst_ctx.rex_w ? R_X86_64_32S : R_X86_64_32;
        }

      howto_ptr = elf_x86_64_rtype_to_howto (abfd, new_r_type);
      r = _bfd_final_link_relocate (howto_ptr, abfd, input_section,
                                    contents, irel->r_offset,
                                    relocation_val, 0);
      if (r == bfd_reloc_overflow)
        return true;

      if (sym_data.abs_symbol)
        {
          if ((new_r_type == R_X86_64_32S && (relocation_val + INT32_MIN_NEGATIVE_VAL) > UINT32_MAX_VALUE_VAL)
              || (new_r_type == R_X86_64_32 && relocation_val > UINT32_MAX_VALUE_VAL))
            return true;
        }

      bfd_put_8 (abfd, new_modrm, contents + roff - 1);

      if (inst_ctx.rex)
        {
          unsigned int modified_rex = (inst_ctx.rex & ~rex_mask_to_clear) | ((inst_ctx.rex & X86_PREFIX_REX_R) >> 2);
          bfd_put_8 (abfd, modified_rex, contents + roff - 3);
        }
      else if (inst_ctx.rex2)
        {
          unsigned int modified_rex2 = (inst_ctx.rex2 & ~rex2_mask_to_clear) | ((inst_ctx.rex2 & (X86_PREFIX_REX_R | (X86_PREFIX_REX_X << 4))) >> 2);
          bfd_put_8 (abfd, modified_rex2, contents + roff - 3);
        }

      irel->r_addend = 0;
      bfd_put_8 (abfd, new_opcode, contents + roff - 2);

      if (inst_ctx.movrs_len)
        {
          bfd_put_8 (abfd, SEGMENT_OVERRIDE_CS_VAL, contents + roff - inst_ctx.movrs_len);
          bfd_put_8 (abfd, SEGMENT_OVERRIDE_CS_VAL, contents + roff - inst_ctx.movrs_len + 1);
          if (inst_ctx.movrs_len == 6)
            {
              bfd_put_8 (abfd, X86_PREFIX_REX2_D5, contents + roff - 4);
              bfd_put_8 (abfd, inst_ctx.rex2, contents + roff - 3);
            }
        }
    }

  *r_type_p = new_r_type;
  irel->r_info = htab->r_info (r_symndx,
                               new_r_type | R_X86_64_converted_reloc_bit);

  *converted = true;

  return true;
}

/* Look through the relocs for a section during the first phase, and
   calculate needed space in the global offset table, and procedure
   linkage table.  */

static bool
elf_x86_64_scan_relocs (bfd *abfd, struct bfd_link_info *info,
			asection *sec,
			const Elf_Internal_Rela *relocs)
{
  struct elf_x86_link_hash_table *htab;
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  bfd_byte *contents = NULL;
  bool converted = false;
  bool result = true;

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

  const Elf_Internal_Rela *rel_end = relocs + sec->reloc_count;
  for (const Elf_Internal_Rela *rel = relocs; rel < rel_end; rel++)
    {
      unsigned int r_type;
      unsigned int r_symndx;
      struct elf_link_hash_entry *h = NULL;
      struct elf_x86_link_hash_entry *eh = NULL;
      Elf_Internal_Sym *isym = NULL;
      const char *name_for_error = NULL;
      bool size_reloc = false;
      bool converted_reloc = false;
      bool no_dynreloc = false;
      reloc_howto_type *howto;

      bool handle_got_ref = false;
      bool update_zero_undefweak_got = false;
      bool handle_pointer_reloc_logic = false;

      r_symndx = htab->r_sym (rel->r_info);
      r_type = ELF32_R_TYPE (rel->r_info);

      if (r_type == R_X86_64_NONE)
	continue;

      if (r_symndx >= NUM_SHDR_ENTRIES (symtab_hdr))
	{
	  _bfd_error_handler (_("%pB: bad symbol index: %d"), abfd, r_symndx);
	  result = false;
	  break;
	}

      howto = elf_x86_64_rtype_to_howto (abfd, r_type);
      if (howto == NULL)
	{
	  _bfd_error_handler (_("%pB: unsupported relocation type %#x"), abfd, r_type);
	  result = false;
	  break;
	}
      if (!bfd_reloc_offset_in_range (howto, abfd, sec, rel->r_offset))
	{
	  _bfd_error_handler
	    (_("%pB: bad reloc offset (%#" PRIx64 " > %#" PRIx64 ") for"
	       " section `%pA'"), abfd, (uint64_t) rel->r_offset,
	     (uint64_t) sec->size, sec);
	  result = false;
	  break;
	}

      if (r_symndx < symtab_hdr->sh_info)
	{
	  isym = bfd_sym_from_r_symndx (&htab->elf.sym_cache, abfd, r_symndx);
	  if (isym == NULL)
	    {
	      result = false;
	      break;
	    }

	  if (ELF_ST_TYPE (isym->st_info) == STT_GNU_IFUNC)
	    {
	      h = _bfd_elf_x86_get_local_sym_hash (htab, abfd, rel, true);
	      if (h == NULL)
		{
		  result = false;
		  break;
		}
	      h->root.root.string = bfd_elf_sym_name (abfd, symtab_hdr, isym, NULL);
	      h->type = STT_GNU_IFUNC;
	      h->def_regular = 1;
	      h->ref_regular = 1;
	      h->forced_local = 1;
	      h->root.type = bfd_link_hash_defined;
	    }
	}
      else
	{
	  h = _bfd_elf_get_link_hash_entry (sym_hashes, r_symndx, symtab_hdr);
	}
      eh = (struct elf_x86_link_hash_entry *) h;

      if (!ABI_64_P (abfd))
	{
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
	      name_for_error = h ? h->root.root.string : bfd_elf_sym_name (abfd, symtab_hdr, isym, NULL);
	      _bfd_error_handler
		(_("%pB: relocation %s against symbol `%s' isn't "
		   "supported in x32 mode"), abfd,
		 x86_64_elf_howto_table[r_type].name, name_for_error);
	      bfd_set_error (bfd_error_bad_value);
	      result = false;
	      break;
	    default:
	      break;
	    }
	  if (!result) break;
	}

      if (h != NULL)
	h->ref_regular = 1;

      if ((r_type == R_X86_64_GOTPCREL
	   || r_type == R_X86_64_GOTPCRELX
	   || r_type == R_X86_64_REX_GOTPCRELX
	   || r_type == R_X86_64_CODE_4_GOTPCRELX
	   || r_type == R_X86_64_CODE_5_GOTPCRELX
	   || r_type == R_X86_64_CODE_6_GOTPCRELX)
	  && (h == NULL || h->type != STT_GNU_IFUNC))
	{
	  Elf_Internal_Rela *irel = (Elf_Internal_Rela *) rel;
	  if (!elf_x86_64_convert_load_reloc (abfd, sec, contents,
					      &r_type, irel, h,
					      &converted_reloc, info))
	    {
	      result = false;
	      break;
	    }

	  if (converted_reloc)
	    converted = true;
	}

      if (!_bfd_elf_x86_valid_reloc_p (sec, info, htab, rel, h, isym,
				       symtab_hdr, &no_dynreloc))
	{
	  result = false;
	  break;
	}

      if (! elf_x86_64_tls_transition (info, abfd, sec, contents,
				       symtab_hdr, sym_hashes,
				       &r_type, GOT_UNKNOWN,
				       rel, rel_end, h, isym, false))
	{
	  result = false;
	  break;
	}

      if (h == htab->elf.hgot)
	htab->got_referenced = true;

      switch (r_type)
	{
	case R_X86_64_TLSLD:
	  htab->tls_ld_or_ldm_got.refcount = 1;
	  update_zero_undefweak_got = true;
	  handle_got_ref = true;
	  break;

	case R_X86_64_TPOFF32:
	  if (!bfd_link_executable (info) && ABI_64_P (abfd))
	    {
	      elf_x86_64_need_pic (info, abfd, sec, h, symtab_hdr, isym,
				   &x86_64_elf_howto_table[r_type]);
	      result = false;
	      break;
	    }
	  if (eh != NULL)
	    eh->zero_undefweak &= 0x2;
	  break;

	case R_X86_64_TLSDESC_CALL:
	  htab->has_tls_desc_call = 1;
	  handle_got_ref = true;
	  break;

	case R_X86_64_GOTTPOFF:
	case R_X86_64_CODE_4_GOTTPOFF:
	case R_X86_64_CODE_5_GOTTPOFF:
	case R_X86_64_CODE_6_GOTTPOFF:
	  if (!bfd_link_executable (info))
	    info->flags |= DF_STATIC_TLS;
	  /* Fall through */
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
	  handle_got_ref = true;
	  break;

	case R_X86_64_PLT32:
	  if (h != NULL)
	    {
	      eh->zero_undefweak &= 0x2;
	      h->needs_plt = 1;
	      h->plt.refcount = 1;
	    }
	  break;

	case R_X86_64_PLTOFF64:
	  if (h != NULL)
	    {
	      h->needs_plt = 1;
	      h->plt.refcount = 1;
	    }
	  handle_got_ref = true;
	  update_zero_undefweak_got = true;
	  break;

	case R_X86_64_SIZE32:
	case R_X86_64_SIZE64:
	  size_reloc = true;
	  handle_pointer_reloc_logic = true;
	  break;

	case R_X86_64_32:
	  if (!ABI_64_P (abfd))
	    {
	      handle_pointer_reloc_logic = true;
	      break;
	    }
	  /* Fall through.  */
	case R_X86_64_8:
	case R_X86_64_16:
	case R_X86_64_32S:
	case R_X86_64_PC8:
	case R_X86_64_PC16:
	case R_X86_64_PC32:
	case R_X86_64_PC64:
	case R_X86_64_64:
	  handle_pointer_reloc_logic = true;
	  break;

	case R_X86_64_CODE_5_GOTPC32_TLSDESC:
	case R_X86_64_CODE_6_GOTPC32_TLSDESC:
	  name_for_error = h ? h->root.root.string : bfd_elf_sym_name (abfd, symtab_hdr, isym, NULL);
	  _bfd_error_handler
	    (_("%pB: unsupported relocation %s against symbol `%s'"),
	     abfd, x86_64_elf_howto_table[r_type].name, name_for_error);
	  bfd_set_error (bfd_error_bad_value);
	  result = false;
	  break;

	case R_X86_64_GNU_VTINHERIT:
	  if (!bfd_elf_gc_record_vtinherit (abfd, sec, h, rel->r_offset))
	    {
	      result = false;
	      break;
	    }
	  break;

	case R_X86_64_GNU_VTENTRY:
	  if (!bfd_elf_gc_record_vtentry (abfd, sec, h, rel->r_addend))
	    {
	      result = false;
	      break;
	    }
	  break;

	default:
	  break;
	}

      if (!result) break;

      if (handle_got_ref)
	{
	  int tls_type, old_tls_type;

	  switch (r_type)
	    {
	    default:
	      tls_type = GOT_NORMAL;
	      if (h)
		{
		  if (ABS_SYMBOL_P (h))
		    tls_type = GOT_ABS;
		}
	      else if (isym && isym->st_shndx == SHN_ABS)
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

	  if (h != NULL)
	    {
	      h->got.refcount = 1;
	      old_tls_type = eh->tls_type;
	    }
	  else
	    {
	      bfd_signed_vma *local_got_refcounts;

	      if (!elf_x86_allocate_local_got_info (abfd,
						    symtab_hdr->sh_info))
		{
		  result = false;
		  break;
		}

		local_got_refcounts = elf_local_got_refcounts (abfd);
		local_got_refcounts[r_symndx] = 1;
		old_tls_type
		  = elf_x86_local_got_tls_type (abfd) [r_symndx];
	    }

	  if (old_tls_type != tls_type && old_tls_type != GOT_UNKNOWN
	      && (! GOT_TLS_GD_ANY_P (old_tls_type)
		  || tls_type != GOT_TLS_IE))
	    {
	      if (old_tls_type == GOT_TLS_IE && GOT_TLS_GD_ANY_P (tls_type))
		tls_type = old_tls_type;
	      else if (GOT_TLS_GD_ANY_P (old_tls_type)
		       && GOT_TLS_GD_ANY_P (tls_type))
		tls_type |= old_tls_type;
	      else
		{
		  name_for_error = h ? h->root.root.string : bfd_elf_sym_name (abfd, symtab_hdr, isym, NULL);
		  _bfd_error_handler
		    (_("%pB: '%s' accessed both as normal and"
		       " thread local symbol"),
		     abfd, name_for_error);
		  bfd_set_error (bfd_error_bad_value);
		  result = false;
		  break;
		}
	    }

	  if (old_tls_type != tls_type)
	    {
	      if (eh != NULL)
		eh->tls_type = tls_type;
	      else
		elf_x86_local_got_tls_type (abfd) [r_symndx] = tls_type;
	    }
	  update_zero_undefweak_got = true;
	}

      if (!result) break;

      if (update_zero_undefweak_got)
	{
	  if (eh != NULL)
	    eh->zero_undefweak &= 0x2;
	}

      if (handle_pointer_reloc_logic)
	{
	  if (!htab->params->no_reloc_overflow_check
	      && !converted_reloc
	      && (bfd_link_pic (info)
		  || (bfd_link_executable (info)
		      && h != NULL
		      && !h->def_regular
		      && h->def_dynamic
		      && (sec->flags & SEC_READONLY) == 0)))
	    {
	      elf_x86_64_need_pic (info, abfd, sec, h, symtab_hdr, isym,
				   &x86_64_elf_howto_table[r_type]);
	      result = false;
	      break;
	    }
	  if (eh != NULL && (sec->flags & SEC_CODE) != 0)
	    eh->zero_undefweak |= 0x2;

	  if (h != NULL
	      && (bfd_link_executable (info)
		  || h->type == STT_GNU_IFUNC))
	    {
	      bool func_pointer_ref = false;

	      if (r_type == R_X86_64_PC32)
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
	      else if (r_type != R_X86_64_PC64)
		{
		  if ((sec->flags & SEC_READONLY) == 0
		      && (r_type == R_X86_64_64
			  || (!ABI_64_P (abfd)
			      && (r_type == R_X86_64_32
				  || r_type == R_X86_64_32S))))
		    func_pointer_ref = true;

		  if (!func_pointer_ref
		      || (bfd_link_pde (info)
			  && h->type == STT_GNU_IFUNC))
		    h->pointer_equality_needed = 1;
		}

	      if (!func_pointer_ref)
		{
		  h->non_got_ref = 1;

		  if (!elf_has_indirect_extern_access (sec->owner))
		    eh->non_got_ref_without_indirect_extern_access = 1;

		  if (!h->def_regular
		      || (sec->flags & (SEC_CODE | SEC_READONLY)) != 0)
		    h->plt.refcount = 1;

		  if (htab->elf.target_os != is_solaris
		      && h->pointer_equality_needed
		      && h->type == STT_FUNC
		      && eh->def_protected
		      && !SYMBOL_DEFINED_NON_SHARED_P (h)
		      && h->def_dynamic)
		    {
		      name_for_error = h->root.root.string;
		      _bfd_error_handler
			(_("%pB: non-canonical reference to canonical "
			   "protected function `%s' in %pB"),
			 abfd, name_for_error,
			 h->root.u.def.section->owner);
		      bfd_set_error (bfd_error_bad_value);
		      result = false;
		      break;
		    }
		}
	    }
	}
      if (!result) break;

      if (!no_dynreloc
	  && NEED_DYNAMIC_RELOCATION_P (true, info, true, h, sec,
					r_type,
					htab->pointer_r_type))
	{
	  struct elf_dyn_relocs *p;
	  struct elf_dyn_relocs **head;

	  if (h != NULL)
		head = &h->dyn_relocs;
	  else
	    {
	      isym = bfd_sym_from_r_symndx (&htab->elf.sym_cache,
					    abfd, r_symndx);
	      if (isym == NULL)
		{
		  result = false;
		  break;
		}

	      asection *s = bfd_section_from_elf_index (abfd, isym->st_shndx);
	      if (s == NULL)
		s = sec;

	      void **vpp = &(elf_section_data (s)->local_dynrel);
	      head = (struct elf_dyn_relocs **)vpp;
	    }

	  p = *head;
	  if (p == NULL || p->sec != sec)
	    {
	      size_t amt = sizeof *p;

	      p = ((struct elf_dyn_relocs *)
		   bfd_alloc (htab->elf.dynobj, amt));
	      if (p == NULL)
		{
		  result = false;
		  break;
		}
	      p->next = *head;
	      *head = p;
	      p->sec = sec;
	      p->count = 0;
	      p->pc_count = 0;
	    }

	  p->count += 1;
	  if (X86_PCREL_TYPE_P (true, r_type) || size_reloc)
		p->pc_count += 1;
	}
    }

  if (elf_section_data (sec)->this_hdr.contents != contents)
    {
      if (result && converted)
	{
	  elf_section_data (sec)->this_hdr.contents = contents;
	  info->cache_size += sec->size;
	}
      else
	_bfd_elf_munmap_section_contents (sec, contents);
    }

  if (result && elf_section_data (sec)->relocs != relocs && converted)
    elf_section_data (sec)->relocs = (Elf_Internal_Rela *) relocs;

  if (!result)
    sec->check_relocs_failed = 1;
  return result;
}

static bool
elf_x86_64_early_size_sections (bfd *output_bfd, struct bfd_link_info *info)
{
  if (info == NULL)
    return false;

  bfd *abfd;

  for (abfd = info->input_bfds; abfd != NULL; abfd = abfd->link.next)
    if (bfd_get_flavour (abfd) == bfd_target_elf_flavour &&
	!_bfd_elf_link_iterate_on_relocs (abfd, info,
					     elf_x86_64_scan_relocs))
      return false;

  return _bfd_x86_elf_early_size_sections (output_bfd, info);
}

/* Return the relocation value for @tpoff relocation
   if STT_TLS virtual address is ADDRESS.  */

static bfd_vma
elf_x86_64_tpoff (struct bfd_link_info *info, bfd_vma address)
{
  struct elf_link_hash_table *htab = elf_hash_table (info);
  if (htab == NULL)
    return 0;

  const struct elf_backend_data *bed = get_elf_backend_data (info->output_bfd);
  if (bed == NULL)
    return 0;

  if (htab->tls_sec == NULL)
    return 0;

  bfd_vma static_tls_size = BFD_ALIGN (htab->tls_size, bed->static_tls_alignment);
  return address - static_tls_size - htab->tls_sec->vma;
}

/* Relocate an x86_64 ELF section.  */

static int
elf_x86_64_relocate_section (bfd *output_bfd,
			     struct bfd_link_info *info,
			     bfd *input_bfd,
			     asection *input_section,
			     bfd_byte *contents,
			     Elf_Internal_Rela *relocs,
			     Elf_Internal_Sym *local_syms,
			     asection **local_sections)
{
  struct elf_x86_link_hash_table *htab;
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  bfd_vma *local_got_offsets;
  bfd_vma *local_tlsdesc_gotents;
  Elf_Internal_Rela *rel;
  Elf_Internal_Rela *wrel;
  Elf_Internal_Rela *relend;
  unsigned int plt_entry_size;
  bool overall_status = true;

  if (input_section->check_relocs_failed)
    return false;

  htab = elf_x86_hash_table (info, X86_64_ELF_DATA);
  if (htab == NULL)
    {
      bfd_set_error (bfd_error_system_error);
      return false;
    }

  if (!is_x86_elf (input_bfd, htab))
    {
      bfd_set_error (bfd_error_wrong_format);
      return false;
    }

  plt_entry_size = htab->plt.plt_entry_size;
  symtab_hdr = &elf_symtab_hdr (input_bfd);
  sym_hashes = elf_sym_hashes (input_bfd);
  local_got_offsets = elf_local_got_offsets (input_bfd);
  local_tlsdesc_gotents = elf_x86_local_tlsdesc_gotent (input_bfd);

  _bfd_x86_elf_set_tls_module_base (info);

  rel = relocs;
  wrel = relocs;
  relend = relocs + input_section->reloc_count;

  while (rel < relend && overall_status)
    {
      unsigned int r_type;
      reloc_howto_type *howto;
      unsigned long r_symndx;
      struct elf_link_hash_entry *h = NULL;
      struct elf_x86_link_hash_entry *eh = NULL;
      Elf_Internal_Sym *sym = NULL;
      asection *sec = NULL;
      bfd_vma relocation_value = 0;
      bool unresolved_reloc = false;
      bfd_reloc_status_type r_status = bfd_reloc_ok;
      bool converted_reloc;
      bfd_vma st_size = 0;
      bool resolved_to_zero;
      bool relative_reloc;
      bool no_copyreloc_p;
      unsigned int initial_r_type; 
      Elf_Internal_Rela *current_rel_start = rel; 

      r_type = ELF32_R_TYPE (rel->r_info);
      initial_r_type = r_type;

      if (r_type == (int) R_X86_64_GNU_VTINHERIT
	  || r_type == (int) R_X86_64_GNU_VTENTRY)
	{
	  *wrel = *rel; 
	  wrel++;
	  rel++;
	  continue;
	}

      converted_reloc = (r_type & R_X86_64_converted_reloc_bit) != 0;
      if (converted_reloc)
	{
	  r_type &= ~R_X86_64_converted_reloc_bit;
	  rel->r_info = htab->r_info (htab->r_sym (rel->r_info), r_type);
	}

      howto = elf_x86_64_rtype_to_howto (input_bfd, r_type);
      if (howto == NULL)
	{
	  overall_status = _bfd_unrecognized_reloc (input_bfd, input_section, r_type);
	  break;
	}

      r_symndx = htab->r_sym (rel->r_info);

      if (r_symndx < symtab_hdr->sh_info)
	{
	  sym = local_syms + r_symndx;
	  sec = local_sections[r_symndx];
	  relocation_value = _bfd_elf_rela_local_sym (output_bfd, sym, &sec, rel);
	  st_size = sym->st_size;

	  if (!bfd_link_relocatable (info) && ELF_ST_TYPE (sym->st_info) == STT_GNU_IFUNC)
	    {
	      h = _bfd_elf_x86_get_local_sym_hash (htab, input_bfd, rel, false);
	      if (h == NULL)
		{
		  bfd_set_error (bfd_error_system_error);
		  overall_status = false;
		  break;
		}
	      h->root.u.def.value = sym->st_value;
	      h->root.u.def.section = sec;
	    }
	}
      else
	{
	  bool warned_dummy ATTRIBUTE_UNUSED;
	  bool ignored_dummy ATTRIBUTE_UNUSED;

	  RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
				   r_symndx, symtab_hdr, sym_hashes,
				   h, sec, relocation_value,
				   unresolved_reloc, warned_dummy, ignored_dummy);
	  if (h) st_size = h->size;
	}

      if (h) eh = (struct elf_x86_link_hash_entry *) h;

      if (sec != NULL && discarded_section (sec))
	{
	  _bfd_clear_contents (howto, input_bfd, input_section,
			       contents, rel->r_offset);
	  wrel->r_offset = rel->r_offset;
	  wrel->r_info = 0;
	  wrel->r_addend = 0;

	  if (bfd_link_relocatable (info)
	      && ((input_section->flags & SEC_DEBUGGING) != 0
		  || elf_section_type (input_section) == SHT_GNU_SFRAME))
	    {
	      if (wrel > relocs) 
		wrel--; 
	      rel++; 
	    }
	  else
	    {
	      wrel++; 
	      rel++; 
	    }
	  continue;
	}

      if (bfd_link_relocatable (info))
	{
	  *wrel = *rel; 
	  wrel++;
	  rel++;
	  continue;
	}

      if (rel->r_addend == 0 && !ABI_64_P (output_bfd))
	{
	  if (r_type == R_X86_64_64)
	    {
	      r_type = R_X86_64_32;
	      memset (contents + rel->r_offset + 4, 0, 4);
	    }
	  else if (r_type == R_X86_64_SIZE64)
	    {
	      r_type = R_X86_64_SIZE32;
	      memset (contents + rel->r_offset + 4, 0, 4);
	    }
	}

      if (h != NULL && h->type == STT_GNU_IFUNC && h->def_regular)
	{
	  const char *name;
	  bfd_vma off;
	  asection *base_got, *resolved_plt;
	  bfd_vma plt_index, plt_offset;

	  if ((input_section->flags & SEC_ALLOC) == 0)
	    {
	      if (elf_section_type (input_section) == SHT_NOTE)
		goto skip_ifunc_label;
	      if ((input_section->flags & SEC_DEBUGGING) != 0)
		goto skip_ifunc_label;
	      bfd_set_error (bfd_error_system_error);
	      overall_status = false;
	      break;
	    }

	  switch (r_type)
	    {
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
		{ bfd_set_error (bfd_error_system_error); overall_status = false; break; }

	      if (off == (bfd_vma) -1)
		{
		  if (h->plt.offset == (bfd_vma) -1)
		    { bfd_set_error (bfd_error_system_error); overall_status = false; break; }

		  if (htab->elf.splt != NULL)
		    {
		      plt_index = (h->plt.offset / plt_entry_size - htab->plt.has_plt0);
		      off = (plt_index + 3) * GOT_ENTRY_SIZE;
		      base_got = htab->elf.sgotplt;
		    }
		  else
		    {
		      plt_index = h->plt.offset / plt_entry_size;
		      off = plt_index * GOT_ENTRY_SIZE;
		      base_got = htab->elf.igotplt;
		    }

		  if (h->dynindx == -1 || h->forced_local || info->symbolic)
		    {
		      if ((off & 1) != 0)
			off &= ~1;
		      else
			{
			  bfd_put_64 (output_bfd, relocation_value, base_got->contents + off);
			  h->got.offset |= 1;
			}
		    }
		}
	      relocation_value = (base_got->output_section->vma + base_got->output_offset + off);
	      goto do_relocation_label;
	    }

	  if (h->plt.offset == (bfd_vma) -1)
	    {
	      if (r_type == htab->pointer_r_type && (input_section->flags & SEC_CODE) == 0)
		goto do_ifunc_pointer_label;
	      goto bad_ifunc_reloc_label;
	    }

	  if (htab->elf.splt != NULL)
	    {
	      if (htab->plt_second != NULL)
		{
		  resolved_plt = htab->plt_second;
		  plt_offset = eh->plt_second.offset;
		}
	      else
		{
		  resolved_plt = htab->elf.splt;
		  plt_offset =  h->plt.offset;
		}
	    }
	  else
	    {
	      resolved_plt = htab->elf.iplt;
	      plt_offset =  h->plt.offset;
	    }

	  relocation_value = (resolved_plt->output_section->vma + resolved_plt->output_offset + plt_offset);

	  switch (r_type)
	    {
	    default:
	    bad_ifunc_reloc_label:
	      name = h->root.root.string ? h->root.root.string : bfd_elf_sym_name (input_bfd, symtab_hdr, sym, NULL);
	      _bfd_error_handler (_("%pB: relocation %s against STT_GNU_IFUNC symbol `%s' isn't supported"),
				  input_bfd, howto->name, name);
	      bfd_set_error (bfd_error_bad_value);
	      overall_status = false;
	      break;

	    case R_X86_64_32S:
	      if (bfd_link_pic (info))
		{ bfd_set_error (bfd_error_system_error); overall_status = false; break; }
	      goto do_relocation_label;

	    case R_X86_64_32:
	      if (ABI_64_P (output_bfd))
		goto do_relocation_label;
	      // FALLTHROUGH
	    case R_X86_64_64:
	    do_ifunc_pointer_label:
	      if (rel->r_addend != 0)
		{
		  name = h->root.root.string ? h->root.root.string : bfd_elf_sym_name (input_bfd, symtab_hdr, sym, NULL);
		  _bfd_error_handler (_("%pB: relocation %s against STT_GNU_IFUNC symbol `%s' has non-zero addend: %" PRId64),
				      input_bfd, howto->name, name, (int64_t) rel->r_addend);
		  bfd_set_error (bfd_error_bad_value);
		  overall_status = false;
		  break;
		}

	      if ((bfd_link_pic (info) && h->non_got_ref) || h->plt.offset == (bfd_vma) -1)
		{
		  Elf_Internal_Rela outrel;
		  asection *sreloc;

		  outrel.r_offset = _bfd_elf_section_offset (output_bfd, info, input_section, rel->r_offset);
		  if (outrel.r_offset == (bfd_vma) -1 || outrel.r_offset == (bfd_vma) -2)
		    { /* Original code aborted for -1, but continued for -2 by memset 0. Keep original flow. */ }

		  outrel.r_offset += (input_section->output_section->vma + input_section->output_offset);

		  if (POINTER_LOCAL_IFUNC_P (info, h))
		    {
		      info->callbacks->minfo (_("Local IFUNC function `%s' in %pB\n"),
						      h->root.root.string, h->root.u.def.section->owner);

		      outrel.r_info = htab->r_info (0, R_X86_64_IRELATIVE);
		      outrel.r_addend = (h->root.u.def.value + h->root.u.def.section->output_section->vma + h->root.u.def.section->output_offset);

		      if (htab->params->report_relative_reloc)
			_bfd_x86_elf_link_report_relative_reloc (info, input_section, h, sym, "R_X86_64_IRELATIVE", &outrel);
		    }
		  else
		    {
		      outrel.r_info = htab->r_info (h->dynindx, r_type);
		      outrel.r_addend = 0;
		    }

		  sreloc = bfd_link_pic (info) ? htab->elf.irelifunc : (htab->elf.splt != NULL ? htab->elf.srelgot : htab->elf.irelplt);
		  elf_append_rela (output_bfd, sreloc, &outrel);
		  rel++; 
		  goto skip_relocation_and_continue_loop; 
		}
	      // FALLTHROUGH
	    case R_X86_64_PC32:
	    case R_X86_64_PC64:
	    case R_X86_64_PLT32:
	      goto do_relocation_label;
	    }
	}
    }
  skip_ifunc_label:;

  resolved_to_zero = (eh != NULL && UNDEFINED_WEAK_RESOLVED_TO_ZERO (info, eh));
  relative_reloc = false; 

  switch (r_type)
    {
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
	{
	    asection *base_got = htab->elf.sgot;
	    bfd_vma off = (bfd_vma) -1;

	    if (htab->elf.sgot == NULL)
		{ bfd_set_error (bfd_error_system_error); overall_status = false; break; }

	    if (h != NULL)
	    {
		off = h->got.offset;
		if (h->needs_plt && h->plt.offset != (bfd_vma)-1 && off == (bfd_vma)-1)
		{
		    bfd_vma plt_index = (h->plt.offset / plt_entry_size - htab->plt.has_plt0);
		    off = (plt_index + 3) * GOT_ENTRY_SIZE;
		    base_got = htab->elf.sgotplt;
		}

		if (RESOLVED_LOCALLY_P (info, h, htab))
		{
		    if ((off & 1) != 0)
			off &= ~1;
		    else
		    {
			bfd_put_64 (output_bfd, relocation_value, base_got->contents + off);
			h->got.offset |= 1;

			if (!info->enable_dt_relr && GENERATE_RELATIVE_RELOC_P (info, h))
			{
			    eh->no_finish_dynamic_symbol = 1;
			    relative_reloc = true;
			}
		    }
		}
	    }
	    else
	    {
		if (local_got_offsets == NULL)
		{ bfd_set_error (bfd_error_system_error); overall_status = false; break; }

		off = local_got_offsets[r_symndx];

		if ((off & 1) != 0)
		    off &= ~1;
		else
		{
		    bfd_put_64 (output_bfd, relocation_value, base_got->contents + off);
		    local_got_offsets[r_symndx] |= 1;

		    if (!info->enable_dt_relr
			&& bfd_link_pic (info)
			&& !(sym->st_shndx == SHN_ABS
			    && (r_type == R_X86_64_GOTPCREL
				|| r_type == R_X86_64_GOTPCRELX
				|| r_type == R_X86_64_REX_GOTPCRELX
				|| r_type == R_X86_64_CODE_4_GOTPCRELX
				|| r_type == R_X86_64_CODE_5_GOTPCRELX
				|| r_type == R_X86_64_CODE_6_GOTPCRELX)))
			relative_reloc = true;
		}
	    }

	    if (relative_reloc)
	    {
		asection *s = htab->elf.srelgot;
		Elf_Internal_Rela outrel;

		if (s == NULL)
		{ bfd_set_error (bfd_error_system_error); overall_status = false; break; }

		outrel.r_offset = (base_got->output_section->vma + base_got->output_offset + off);
		outrel.r_info = htab->r_info (0, R_X86_64_RELATIVE);
		outrel.r_addend = relocation_value;

		if (htab->params->report_relative_reloc)
		    _bfd_x86_elf_link_report_relative_reloc
			(info, input_section, h, sym, "R_X86_64_RELATIVE", &outrel);

		elf_append_rela (output_bfd, s, &outrel);
	    }

	    if (off >= (bfd_vma) -2)
		{ bfd_set_error (bfd_error_system_error); overall_status = false; break; }

	    relocation_value = base_got->output_section->vma + base_got->output_offset + off;
	    if (r_type != R_X86_64_GOTPCREL
		&& r_type != R_X86_64_GOTPCRELX
		&& r_type != R_X86_64_REX_GOTPCRELX
		&& r_type != R_X86_64_CODE_4_GOTPCRELX
		&& r_type != R_X86_64_CODE_5_GOTPCRELX
		&& r_type != R_X86_64_CODE_6_GOTPCRELX
		&& r_type != R_X86_64_GOTPCREL64)
		relocation_value -= htab->elf.sgotplt->output_section->vma - htab->elf.sgotplt->output_offset;
	}
	break;

    case R_X86_64_GOTOFF64:
	{
	    if (bfd_link_pic (info) && h)
	    {
		if (!h->def_regular)
		{
		    const char *v = NULL;
		    switch (ELF_ST_VISIBILITY (h->other))
		    {
		    case STV_HIDDEN:   v = _("hidden symbol");   break;
		    case STV_INTERNAL: v = _("internal symbol"); break;
		    case STV_PROTECTED:v = _("protected symbol");break;
		    default:           v = _("symbol");          break;
		    }
		    _bfd_error_handler (_("%pB: relocation R_X86_64_GOTOFF64 against undefined %s `%s' can not be used when making a shared object"),
					input_bfd, v, h->root.root.string);
		    bfd_set_error (bfd_error_bad_value);
		    overall_status = false;
		    break;
		}
		else if (!bfd_link_executable (info)
			&& !SYMBOL_REFERENCES_LOCAL_P (info, h)
			&& (h->type == STT_FUNC || h->type == STT_OBJECT)
			&& ELF_ST_VISIBILITY (h->other) == STV_PROTECTED)
		{
		    _bfd_error_handler (_("%pB: relocation R_X86_64_GOTOFF64 against protected %s `%s' can not be used when making a shared object"),
					input_bfd, h->type == STT_FUNC ? "function" : "data", h->root.root.string);
		    bfd_set_error (bfd_error_bad_value);
		    overall_status = false;
		    break;
		}
	    }
	    relocation_value -= htab->elf.sgotplt->output_section->vma + htab->elf.sgotplt->output_offset;
	}
	break;

    case R_X86_64_GOTPC32:
    case R_X86_64_GOTPC64:
	relocation_value = htab->elf.sgotplt->output_section->vma + htab->elf.sgotplt->output_offset;
	unresolved_reloc = false;
	break;

    case R_X86_64_PLTOFF64:
	{
	    asection *resolved_plt = NULL;
	    bfd_vma plt_offset = 0;
	    if (h != NULL && (h->plt.offset != (bfd_vma) -1 || eh->plt_got.offset != (bfd_vma) -1) && htab->elf.splt != NULL)
	    {
		if (eh->plt_got.offset != (bfd_vma) -1)
		{ resolved_plt = htab->plt_got; plt_offset = eh->plt_got.offset; }
		else if (htab->plt_second != NULL)
		{ resolved_plt = htab->plt_second; plt_offset = eh->plt_second.offset; }
		else
		{ resolved_plt = htab->elf.splt; plt_offset = h->plt.offset; }

		relocation_value = (resolved_plt->output_section->vma + resolved_plt->output_offset + plt_offset);
		unresolved_reloc = false;
	    }
	    relocation_value -= htab->elf.sgotplt->output_section->vma + htab->elf.sgotplt->output_offset;
	}
	break;

    case R_X86_64_PLT32:
	{
	    asection *resolved_plt = NULL;
	    bfd_vma plt_offset = 0;

	    if (h != NULL && ((h->plt.offset != (bfd_vma) -1 || eh->plt_got.offset != (bfd_vma) -1) && htab->elf.splt != NULL))
	    {
		if (h->plt.offset != (bfd_vma) -1)
		{
		    if (htab->plt_second != NULL)
		    { resolved_plt = htab->plt_second; plt_offset = eh->plt_second.offset; }
		    else
		    { resolved_plt = htab->elf.splt; plt_offset = h->plt.offset; }
		}
		else
		{ resolved_plt = htab->plt_got; plt_offset = eh->plt_got.offset; }

		relocation_value = (resolved_plt->output_section->vma + resolved_plt->output_offset + plt_offset);
		unresolved_reloc = false;
	    }
	}
	break;

    case R_X86_64_SIZE32:
    case R_X86_64_SIZE64:
	relocation_value = st_size;
	goto direct_relocation_label;

    case R_X86_64_PC8:
    case R_X86_64_PC16:
    case R_X86_64_PC32:
	{
	    no_copyreloc_p = (info->nocopyreloc
				|| (h != NULL
				    && !h->root.linker_def
				    && !h->root.ldscript_def
				    && eh->def_protected));

	    if ((input_section->flags & SEC_ALLOC) != 0
		&& (input_section->flags & SEC_READONLY) != 0
		&& h != NULL
		&& ((bfd_link_executable (info)
		    && ((h->root.type == bfd_link_hash_undefweak
			&& (eh == NULL || !UNDEFINED_WEAK_RESOLVED_TO_ZERO (info, eh)))
			|| (bfd_link_pie (info) && !SYMBOL_DEFINED_NON_SHARED_P (h) && h->def_dynamic)
			|| (no_copyreloc_p && h->def_dynamic && !(h->root.u.def.section->flags & SEC_CODE))))
		    || (bfd_link_pie (info) && h->root.type == bfd_link_hash_undefweak)
		    || bfd_link_dll (info)))
	    {
		bool fail = false;
		if (SYMBOL_REFERENCES_LOCAL_P (info, h))
		    fail = !SYMBOL_DEFINED_NON_SHARED_P (h);
		else if (bfd_link_pie (info))
		{
		    if (h->root.type == bfd_link_hash_undefweak || (h->type == STT_FUNC && (sec->flags & SEC_CODE) != 0))
			fail = true;
		}
		else if (no_copyreloc_p || bfd_link_dll (info))
		{
		    fail = (ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
			    || ELF_ST_VISIBILITY (h->other) == STV_PROTECTED);
		}
		if (fail)
		{
		    overall_status = elf_x86_64_need_pic (info, input_bfd, input_section, h, NULL, NULL, howto);
		    break;
		}
	    }
	    else if (h != NULL
		    && (input_section->flags & SEC_CODE) == 0
		    && bfd_link_pie (info)
		    && h->type == STT_FUNC
		    && !h->def_regular
		    && h->def_dynamic)
	    {
		// use_plt label
		asection *resolved_plt = NULL;
		bfd_vma plt_offset = 0;
		if (h->plt.offset != (bfd_vma) -1)
		{
		    if (htab->plt_second != NULL)
		    { resolved_plt = htab->plt_second; plt_offset = eh->plt_second.offset; }
		    else
		    { resolved_plt = htab->elf.splt; plt_offset = h->plt.offset; }
		}
		else
		{ resolved_plt = htab->plt_got; plt_offset = eh->plt_got.offset; }

		relocation_value = (resolved_plt->output_section->vma + resolved_plt->output_offset + plt_offset);
		unresolved_reloc = false;
	    }
	}
	// FALLTHROUGH

    case R_X86_64_8:
    case R_X86_64_16:
    case R_X86_64_32:
    case R_X86_64_PC64:
    case R_X86_64_64:
    direct_relocation_label:
	if ((input_section->flags & SEC_ALLOC) == 0)
	    break;

	need_copy_reloc_in_pie = (bfd_link_pie (info)
				    && h != NULL
				    && (h->needs_copy
					|| eh->needs_copy
					|| (h->root.type
					    == bfd_link_hash_undefined))
				    && (X86_PCREL_TYPE_P (true, r_type)
					|| X86_SIZE_TYPE_P (true,
							    r_type)));

	if (GENERATE_DYNAMIC_RELOCATION_P (true, info, eh, r_type, sec,
					    need_copy_reloc_in_pie,
					    resolved_to_zero, false))
	{
	    Elf_Internal_Rela outrel;
	    bool skip_this_rel = false;
	    bool generate_dynamic_reloc_now = true;
	    asection *sreloc;
	    const char *relative_reloc_name = NULL;

	    outrel.r_offset = _bfd_elf_section_offset (output_bfd, info, input_section, rel->r_offset);
	    if (outrel.r_offset == (bfd_vma) -1 || outrel.r_offset == (bfd_vma) -2)
		skip_this_rel = true;

	    outrel.r_offset += (input_section->output_section->vma
				+ input_section->output_offset);

	    if (skip_this_rel)
		memset (&outrel, 0, sizeof outrel);
	    else if (COPY_INPUT_RELOC_P (true, info, h, r_type))
	    {
		outrel.r_info = htab->r_info (h->dynindx, r_type);
		outrel.r_addend = rel->r_addend;
	    }
	    else
	    {
		if (r_type == htab->pointer_r_type
		    || (r_type == R_X86_64_32
			&& htab->params->no_reloc_overflow_check))
		{
		    if (info->enable_dt_relr)
			generate_dynamic_reloc_now = false;
		    else
		    {
			r_type = R_X86_64_RELATIVE;
			outrel.r_info = htab->r_info (0, R_X86_64_RELATIVE);
			outrel.r_addend = relocation_value + rel->r_addend;
			relative_reloc_name = "R_X86_64_RELATIVE";
		    }
		}
		else if (r_type == R_X86_64_64
			&& !ABI_64_P (output_bfd))
		{
		    r_type = R_X86_64_RELATIVE64;
		    outrel.r_info = htab->r_info (0,
						R_X86_64_RELATIVE64);
		    outrel.r_addend = relocation_value + rel->r_addend;
		    relative_reloc_name = "R_X86_64_RELATIVE64";
		    if ((outrel.r_addend & 0x80000000)
			!= (rel->r_addend & 0x80000000))
		    {
			const char *name_ptr = h ? h->root.root.string : bfd_elf_sym_name (input_bfd, symtab_hdr, sym, NULL);
			_bfd_error_handler (_("%pB: addend %s%#x in relocation %s against symbol `%s' at %#" PRIx64 " in section `%pA' is out of range"),
					    input_bfd, rel->r_addend < 0 ? "-" : "", (int) rel->r_addend, howto->name, name_ptr, (uint64_t) rel->r_offset, input_section);
			bfd_set_error (bfd_error_bad_value);
			overall_status = false;
			break;
		    }
		}
		else
		{
		    long sindx;

		    if (bfd_is_abs_section (sec))
			sindx = 0;
		    else if (sec == NULL || sec->owner == NULL)
		    {
			bfd_set_error (bfd_error_bad_value);
			overall_status = false;
			break;
		    }
		    else
		    {
			asection *osec = sec->output_section;
			sindx = elf_section_data (osec)->dynindx;
			if (sindx == 0)
			{
			    asection *oi = htab->elf.text_index_section;
			    sindx = elf_section_data (oi)->dynindx;
			}
			BFD_ASSERT (sindx != 0);
		    }
		    outrel.r_info = htab->r_info (sindx, r_type);
		    outrel.r_addend = relocation_value + rel->r_addend;
		}
	    }

	    if (generate_dynamic_reloc_now)
	    {
		sreloc = elf_section_data (input_section)->sreloc;

		if (sreloc == NULL || sreloc->contents == NULL)
		{
		    r_status = bfd_reloc_notsupported;
		    goto check_relocation_error_label;
		}

		if (relative_reloc_name
		    && htab->params->report_relative_reloc)
		    _bfd_x86_elf_link_report_relative_reloc
			(info, input_section, h, sym,
			relative_reloc_name, &outrel);

		elf_append_rela (output_bfd, sreloc, &outrel);
	    }
	    
	    if (!(r_type == R_X86_64_RELATIVE || r_type == R_X86_64_RELATIVE64))
	    {
		rel++; 
		goto skip_relocation_and_continue_loop; 
	    }
	}
	break;

    case R_X86_64_TLSGD:
    case R_X86_64_GOTPC32_TLSDESC:
    case R_X86_64_CODE_4_GOTPC32_TLSDESC:
    case R_X86_64_TLSDESC_CALL:
    case R_X86_64_GOTTPOFF:
    case R_X86_64_CODE_4_GOTTPOFF:
    case R_X86_64_CODE_5_GOTTPOFF:
    case R_X86_64_CODE_6_GOTTPOFF:
	{
	    int tls_type = GOT_UNKNOWN;
	    if (h == NULL && local_got_offsets)
		tls_type = elf_x86_local_got_tls_type (input_bfd) [r_symndx];
	    else if (h != NULL)
		tls_type = elf_x86_hash_entry (h)->tls_type;

	    unsigned int r_type_tls = r_type;

	    if (! elf_x86_64_tls_transition (info, input_bfd, input_section, contents,
					    symtab_hdr, sym_hashes,
					    &r_type_tls, tls_type, rel, relend, h, sym, true))
	    { overall_status = false; break; }

	    if (r_type_tls == R_X86_64_TPOFF32)
	    {
		bfd_vma roff = rel->r_offset;

		if (roff >= input_section->size)
		{ info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }

		if (r_type == R_X86_64_TLSGD)
		{
		    int largepic = 0;
		    if (ABI_64_P (output_bfd))
		    {
			if (roff + 5 >= input_section->size)
			{ info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
			if (contents[roff + 5] == 0xb8)
			{
			    if (roff < 3 || (roff - 3 + 22) > input_section->size)
			    { info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
			    memcpy (contents + roff - 3,
				    "\x64\x48\x8b\x04\x25\0\0\0\0\x48\x8d\x80"
				    "\0\0\0\0\x66\x0f\x1f\x44\0", 22);
			    largepic = 1;
			}
			else
			{
			    if (roff < 4 || (roff - 4 + 16) > input_section->size)
			    { info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
			    memcpy (contents + roff - 4,
				    "\x64\x48\x8b\x04\x25\0\0\0\0\x48\x8d\x80\0\0\0",
				    16);
			}
		    }
		    else
		    {
			if (roff < 3 || (roff - 3 + 15) > input_section->size)
			{ info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
			memcpy (contents + roff - 3,
				"\x64\x8b\x04\x25\0\0\0\0\x48\x8d\x80\0\0\0",
				15);
		    }

		    if (roff + 8 + largepic >= input_section->size)
		    { info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }

		    bfd_put_32 (output_bfd,
				elf_x86_64_tpoff (info, relocation_value),
				contents + roff + 8 + largepic);
		    rel++; 
		    rel++; 
		    goto skip_relocation_and_continue_loop;
		}
		else if (r_type == R_X86_64_GOTPC32_TLSDESC)
		{
		    unsigned int val, type_byte;

		    if (roff < 3)
		    { info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
		    type_byte = bfd_get_8 (input_bfd, contents + roff - 3);
		    val = bfd_get_8 (input_bfd, contents + roff - 1);
		    bfd_put_8 (output_bfd,
				(type_byte & 0x48) | ((type_byte >> 2) & 1),
				contents + roff - 3);
		    bfd_put_8 (output_bfd, 0xc7, contents + roff - 2);
		    bfd_put_8 (output_bfd, 0xc0 | ((val >> 3) & 7),
				contents + roff - 1);
		    bfd_put_32 (output_bfd,
				elf_x86_64_tpoff (info, relocation_value),
				contents + roff);
		    rel++;
		    goto skip_relocation_and_continue_loop;
		}
		else if (r_type == R_X86_64_CODE_4_GOTPC32_TLSDESC)
		{
		    unsigned int val, rex2_byte;
		    unsigned int rex2_mask = REX_R | (REX_R << 4);

		    if (roff < 4)
		    { info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
		    rex2_byte = bfd_get_8 (input_bfd, contents + roff - 3);
		    val = bfd_get_8 (input_bfd, contents + roff - 1);
		    bfd_put_8 (output_bfd,
				((rex2_byte & ~rex2_mask)
				| (rex2_byte & rex2_mask) >> 2),
				contents + roff - 3);
		    bfd_put_8 (output_bfd, 0xc7, contents + roff - 2);
		    bfd_put_8 (output_bfd, 0xc0 | ((val >> 3) & 7),
				contents + roff - 1);
		    bfd_put_32 (output_bfd,
				elf_x86_64_tpoff (info, relocation_value),
				contents + roff);
		    rel++;
		    goto skip_relocation_and_continue_loop;
		}
		else if (r_type == R_X86_64_TLSDESC_CALL)
		{
		    unsigned int prefix = 0;
		    if (!ABI_64_P (input_bfd))
		    {
			if (contents[roff] == 0x67)
			    prefix = 1;
		    }
		    if (prefix)
		    {
			if (roff + 2 >= input_section->size)
			{ info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }

			bfd_put_8 (output_bfd, 0x0f, contents + roff);
			bfd_put_8 (output_bfd, 0x1f, contents + roff + 1);
			bfd_put_8 (output_bfd, 0x00, contents + roff + 2);
		    }
		    else
		    {
			if (roff + 1 >= input_section->size)
			{ info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }

			bfd_put_8 (output_bfd, 0x66, contents + roff);
			bfd_put_8 (output_bfd, 0x90, contents + roff + 1);
		    }
		    rel++;
		    goto skip_relocation_and_continue_loop;
		}
		else if (r_type == R_X86_64_GOTTPOFF)
		{
		    unsigned int val, type_byte, reg;

		    if (roff >= 3)
			val = bfd_get_8 (input_bfd, contents + roff - 3);
		    else
		    {
			if (roff < 2)
			{ info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
			val = 0;
		    }
		    type_byte = bfd_get_8 (input_bfd, contents + roff - 2);
		    reg = bfd_get_8 (input_bfd, contents + roff - 1);
		    reg >>= 3;
		    if (type_byte == 0x8b)
		    {
			if (val == 0x4c)
			{
			    if (roff < 3)
				{ info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
			    bfd_put_8 (output_bfd, 0x49,
					contents + roff - 3);
			}
			else if (!ABI_64_P (output_bfd) && val == 0x44)
			{
			    if (roff < 3)
				{ info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
			    bfd_put_8 (output_bfd, 0x41,
					contents + roff - 3);
			}
			bfd_put_8 (output_bfd, 0xc7,
					contents + roff - 2);
			bfd_put_8 (output_bfd, 0xc0 | reg,
					contents + roff - 1);
		    }
		    else if (reg == 4)
		    {
			if (val == 0x4c)
			{
			    if (roff < 3)
				{ info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
			    bfd_put_8 (output_bfd, 0x49,
					contents + roff - 3);
			}
			else if (!ABI_64_P (output_bfd) && val == 0x44)
			{
			    if (roff < 3)
				{ info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
			    bfd_put_8 (output_bfd, 0x41,
					contents + roff - 3);
			}
			bfd_put_8 (output_bfd, 0x81,
					contents + roff - 2);
			bfd_put_8 (output_bfd, 0xc0 | reg,
					contents + roff - 1);
		    }
		    else
		    {
			if (val == 0x4c)
			{
			    if (roff < 3)
				{ info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
			    bfd_put_8 (output_bfd, 0x4d,
					contents + roff - 3);
			}
			else if (!ABI_64_P (output_bfd) && val == 0x44)
			{
			    if (roff < 3)
				{ info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
			    bfd_put_8 (output_bfd, 0x45,
					contents + roff - 3);
			}
			bfd_put_8 (output_bfd, 0x8d,
					contents + roff - 2);
			bfd_put_8 (output_bfd, 0x80 | reg | (reg << 3),
					contents + roff - 1);
		    }
		    bfd_put_32 (output_bfd,
				elf_x86_64_tpoff (info, relocation_value),
				contents + roff);
		    rel++;
		    goto skip_relocation_and_continue_loop;
		}
		else if (r_type == R_X86_64_CODE_4_GOTTPOFF)
		{
		    unsigned int rex2_byte, type_byte, reg_byte;
		    unsigned int rex2_mask = REX_R | (REX_R << 4);

		    if (roff < 4)
		    { info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }

		    rex2_byte = bfd_get_8 (input_bfd, contents + roff - 3);
		    type_byte = bfd_get_8 (input_bfd, contents + roff - 2);
		    reg_byte = bfd_get_8 (input_bfd, contents + roff - 1);
		    reg_byte >>= 3;
		    if (type_byte == 0x8b)
		    {
			if (bfd_get_8 (input_bfd, contents + roff - 4) == 0x0f)
			{
			    bfd_put_8 (output_bfd, 0x2e, contents + roff - 4);
			    rex2_byte = 0x2e;
			    rex2_mask = 0;
			}
			type_byte = 0xc7;
		    }
		    else
			type_byte = 0x81;
		    bfd_put_8 (output_bfd,
				((rex2_byte & ~rex2_mask)
				| (rex2_byte & rex2_mask) >> 2),
				contents + roff - 3);
		    bfd_put_8 (output_bfd, type_byte,
				contents + roff - 2);
		    bfd_put_8 (output_bfd, 0xc0 | reg_byte,
				contents + roff - 1);
		    bfd_put_32 (output_bfd,
				elf_x86_64_tpoff (info, relocation_value),
				contents + roff);
		    rel++;
		    goto skip_relocation_and_continue_loop;
		}
		else if (r_type == R_X86_64_CODE_5_GOTTPOFF)
		{
		    unsigned int rex_byte = bfd_get_8 (input_bfd, contents + roff - 5);

		    rex_byte = (rex_byte & ~(REX_R | REX_B))
				| ((rex_byte & REX_R) / (REX_R / REX_B));

		    unsigned int reg_byte = bfd_get_8 (input_bfd, contents + roff - 1);
		    reg_byte >>= 3;

		    bfd_put_8 (output_bfd, 0x2e, contents + roff - 5);
		    bfd_put_8 (output_bfd, 0x2e, contents + roff - 4);
		    bfd_put_8 (output_bfd, rex_byte, contents + roff - 3);
		    bfd_put_8 (output_bfd, 0xc7, contents + roff - 2);
		    bfd_put_8 (output_bfd, 0xc0 | reg_byte, contents + roff - 1);

		    bfd_put_32 (output_bfd,
				elf_x86_64_tpoff (info, relocation_value),
				contents + roff);
		    rel++;
		    goto skip_relocation_and_continue_loop;
		}
		else if (r_type == R_X86_64_CODE_6_GOTTPOFF)
		{
		    unsigned int type_byte, reg_byte, byte1_evex;

		    if (roff < 6)
		    { info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }

		    byte1_evex = bfd_get_8 (input_bfd, contents + roff - 5);
		    type_byte = bfd_get_8 (input_bfd, contents + roff - 2);
		    reg_byte = bfd_get_8 (input_bfd, contents + roff - 1);
		    reg_byte >>= 3;

		    if (type_byte == 0x8b)
		    {
			unsigned int rex2 = 0;

			if (!(byte1_evex & (1 << 7)))
			    rex2 |= REX_B;
			if (!(byte1_evex & (1 << 4)))
			    rex2 |= REX_B << 4;
			type_byte = bfd_get_8 (input_bfd, contents + roff - 4);
			if (type_byte & (1 << 7))
			    rex2 |= REX_W;


			bfd_put_8 (output_bfd, 0x2e, contents + roff - 6);
			bfd_put_8 (output_bfd, 0x2e, contents + roff - 5);
			bfd_put_8 (output_bfd, 0xd5, contents + roff - 4);
			bfd_put_8 (output_bfd, rex2, contents + roff - 3);
			bfd_put_8 (output_bfd, 0xc7, contents + roff - 2);
			bfd_put_8 (output_bfd, 0xc0 | reg_byte, contents + roff - 1);
			bfd_put_32 (output_bfd,
					elf_x86_64_tpoff (info, relocation_value),
					contents + roff);
			rel++;
			goto skip_relocation_and_continue_loop;
		    }

		    byte1_evex = evex_move_r_to_b (byte1_evex, false);
		    bfd_put_8 (output_bfd, byte1_evex, contents + roff - 5);
		    bfd_put_8 (output_bfd, 0x81, contents + roff - 2);
		    bfd_put_8 (output_bfd, 0xc0 | reg_byte, contents + roff - 1);
		    bfd_put_32 (output_bfd,
				elf_x86_64_tpoff (info, relocation_value),
				contents + roff);
		    rel++;
		    goto skip_relocation_and_continue_loop;
		}
		else
		    BFD_ASSERT (false);
	    }

	    if (htab->elf.sgot == NULL)
		{ bfd_set_error (bfd_error_system_error); overall_status = false; break; }

	    bfd_vma off_got;
	    bfd_vma off_plt;
	    if (h != NULL)
	    {
		off_got = h->got.offset;
		off_plt = elf_x86_hash_entry (h)->tlsdesc_got;
	    }
	    else
	    {
		if (local_got_offsets == NULL)
		{ bfd_set_error (bfd_error_system_error); overall_status = false; break; }

		off_got = local_got_offsets[r_symndx];
		off_plt = local_tlsdesc_gotents[r_symndx];
	    }

	    if ((off_got & 1) != 0)
		off_got &= ~1;
	    else
	    {
		Elf_Internal_Rela outrel;
		int dr_type, indx;
		asection *sreloc;

		if (htab->elf.srelgot == NULL)
		{ bfd_set_error (bfd_error_system_error); overall_status = false; break; }

		indx = h && h->dynindx != -1 ? h->dynindx : 0;

		if (GOT_TLS_GDESC_P (tls_type))
		{
		    outrel.r_info = htab->r_info (indx, R_X86_64_TLSDESC);
		    BFD_ASSERT (htab->sgotplt_jump_table_size + off_plt
				+ 2 * GOT_ENTRY_SIZE <= htab->elf.sgotplt->size);
		    outrel.r_offset = (htab->elf.sgotplt->output_section->vma
					+ htab->elf.sgotplt->output_offset
					+ off_plt + htab->sgotplt_jump_table_size);
		    sreloc = htab->rel_tls_desc;
		    if (indx == 0)
			outrel.r_addend = relocation_value - _bfd_x86_elf_dtpoff_base (info);
		    else
			outrel.r_addend = 0;
		    elf_append_rela (output_bfd, sreloc, &outrel);
		}

		sreloc = htab->elf.srelgot;

		outrel.r_offset = (htab->elf.sgot->output_section->vma
				    + htab->elf.sgot->output_offset + off_got);

		if (GOT_TLS_GD_P (tls_type))
		    dr_type = R_X86_64_DTPMOD64;
		else if (GOT_TLS_GDESC_P (tls_type))
		    goto dr_done_label;
		else
		    dr_type = R_X86_64_TPOFF64;

		bfd_put_64 (output_bfd, 0, htab->elf.sgot->contents + off_got);
		outrel.r_addend = 0;
		if ((dr_type == R_X86_64_TPOFF64
			|| dr_type == R_X86_64_TLSDESC) && indx == 0)
		    outrel.r_addend = relocation_value - _bfd_x86_elf_dtpoff_base (info);
		outrel.r_info = htab->r_info (indx, dr_type);

		elf_append_rela (output_bfd, sreloc, &outrel);

		if (GOT_TLS_GD_P (tls_type))
		{
		    if (indx == 0)
		    {
			BFD_ASSERT (! unresolved_reloc);
			bfd_put_64 (output_bfd,
				    relocation_value - _bfd_x86_elf_dtpoff_base (info),
				    htab->elf.sgot->contents + off_got + GOT_ENTRY_SIZE);
		    }
		    else
		    {
			bfd_put_64 (output_bfd, 0,
				    htab->elf.sgot->contents + off_got + GOT_ENTRY_SIZE);
			outrel.r_info = htab->r_info (indx,
							R_X86_64_DTPOFF64);
			outrel.r_offset += GOT_ENTRY_SIZE;
			elf_append_rela (output_bfd, sreloc,
							&outrel);
		    }
		}

	    dr_done_label:
		if (h != NULL)
		    h->got.offset |= 1;
		else
		    local_got_offsets[r_symndx] |= 1;
	    }

	    if (off_got >= (bfd_vma) -2
		&& ! GOT_TLS_GDESC_P (tls_type))
		{ bfd_set_error (bfd_error_system_error); overall_status = false; break; }
	    if (r_type_tls == r_type)
	    {
		if (r_type == R_X86_64_GOTPC32_TLSDESC
		    || r_type == R_X86_64_CODE_4_GOTPC32_TLSDESC
		    || r_type == R_X86_64_TLSDESC_CALL)
		    relocation_value = htab->elf.sgotplt->output_section->vma
			+ htab->elf.sgotplt->output_offset
			+ off_plt + htab->sgotplt_jump_table_size;
		else
		    relocation_value = htab->elf.sgot->output_section->vma
			+ htab->elf.sgot->output_offset + off_got;
		unresolved_reloc = false;
	    }
	    else
	    {
		bfd_vma roff = rel->r_offset;

		if (r_type == R_X86_64_TLSGD)
		{
		    int largepic = 0;
		    if (ABI_64_P (output_bfd))
		    {
			if (contents[roff + 5] == 0xb8)
			{
			    if (roff < 3
				|| (roff - 3 + 22) > input_section->size)
			    { info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
			    memcpy (contents + roff - 3,
				    "\x64\x48\x8b\x04\x25\0\0\0\0\x48\x03\x05"
				    "\0\0\0\0\x66\x0f\x1f\x44\0", 22);
			    largepic = 1;
			}
			else
			{
			    if (roff < 4
				|| (roff - 4 + 16) > input_section->size)
			    { info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
			    memcpy (contents + roff - 4,
				    "\x64\x48\x8b\x04\x25\0\0\0\0\x48\x03\x05\0\0\0",
				    16);
			}
		    }
		    else
		    {
			if (roff < 3
				|| (roff - 3 + 15) > input_section->size)
			{ info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
			memcpy (contents + roff - 3,
				"\x64\x8b\x04\x25\0\0\0\0\x48\x03\x05\0\0\0",
				15);
		    }

		    relocation_value = (htab->elf.sgot->output_section->vma
					+ htab->elf.sgot->output_offset + off_got
					- roff
					- largepic
					- input_section->output_section->vma
					- input_section->output_offset
					- 12);
		    bfd_put_32 (output_bfd, relocation_value,
				contents + roff + 8 + largepic);
		    rel++;
		    rel++;
		    goto skip_relocation_and_continue_loop;
		}
		else if (r_type == R_X86_64_GOTPC32_TLSDESC
			|| r_type == R_X86_64_CODE_4_GOTPC32_TLSDESC)
		{
		    if (roff < 2)
		    { info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
		    bfd_put_8 (output_bfd, 0x8b, contents + roff - 2);

		    bfd_put_32 (output_bfd,
				htab->elf.sgot->output_section->vma
				+ htab->elf.sgot->output_offset + off_got
				- rel->r_offset
				- input_section->output_section->vma
				- input_section->output_offset
				- 4,
				contents + roff);
		    rel++;
		    goto skip_relocation_and_continue_loop;
		}
		else if (r_type == R_X86_64_TLSDESC_CALL)
		{
		    unsigned int prefix = 0;
		    if (!ABI_64_P (input_bfd))
		    {
			if (contents[roff] == 0x67)
			    prefix = 1;
		    }
		    if (prefix)
		    {
			bfd_put_8 (output_bfd, 0x0f, contents + roff);
			bfd_put_8 (output_bfd, 0x1f, contents + roff + 1);
			bfd_put_8 (output_bfd, 0x00, contents + roff + 2);
		    }
		    else
		    {
			bfd_put_8 (output_bfd, 0x66, contents + roff);
			bfd_put_8 (output_bfd, 0x90, contents + roff + 1);
		    }
		    rel++;
		    goto skip_relocation_and_continue_loop;
		}
		else
		    BFD_ASSERT (false);
	    }
	}
	break;

    case R_X86_64_TLSLD:
	{
	    unsigned int r_type_tls = r_type;

	    if (! elf_x86_64_tls_transition (info, input_bfd,
					    input_section, contents,
					    symtab_hdr, sym_hashes,
					    &r_type_tls, GOT_UNKNOWN, rel,
					    relend, h, sym, true))
	    { overall_status = false; break; }

	    if (r_type_tls != R_X86_64_TLSLD)
	    {
		BFD_ASSERT (r_type_tls == R_X86_64_TPOFF32);
		if (ABI_64_P (output_bfd))
		{
		    if ((rel->r_offset + 5) >= input_section->size)
		    { info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
		    if (contents[rel->r_offset + 5] == 0xb8)
		    {
			if (rel->r_offset < 3
				|| (rel->r_offset - 3 + 22) > input_section->size)
			{ info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
			memcpy (contents + rel->r_offset - 3,
				"\x66\x66\x66\x66\x2e\x0f\x1f\x84\0\0\0\0\0"
				"\x64\x48\x8b\x04\x25\0\0\0", 22);
		    }
		    else if (contents[rel->r_offset + 4] == 0xff
				|| contents[rel->r_offset + 4] == 0x67)
		    {
			if (rel->r_offset < 3
				|| (rel->r_offset - 3 + 13) > input_section->size)
			{ info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
			memcpy (contents + rel->r_offset - 3,
				"\x66\x66\x66\x66\x64\x48\x8b\x04\x25\0\0\0",
				13);

		    }
		    else
		    {
			if (rel->r_offset < 3
				|| (rel->r_offset - 3 + 12) > input_section->size)
			{ info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
			memcpy (contents + rel->r_offset - 3,
				"\x66\x66\x66\x64\x48\x8b\x04\x25\0\0\0", 12);
		    }
		}
		else
		{
		    if ((rel->r_offset + 4) >= input_section->size)
		    { info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
		    if (contents[rel->r_offset + 4] == 0xff)
		    {
			if (rel->r_offset < 3
				|| (rel->r_offset - 3 + 13) > input_section->size)
			{ info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
			memcpy (contents + rel->r_offset - 3,
				"\x66\x0f\x1f\x40\x00\x64\x8b\x04\x25\0\0\0",
				13);
		    }
		    else
		    {
			if (rel->r_offset < 3
				|| (rel->r_offset - 3 + 12) > input_section->size)
			{ info->callbacks->fatal (_("%P: corrupt input: %pB\n"), input_bfd); bfd_set_error (bfd_error_invalid_input_data); overall_status = false; break; }
			memcpy (contents + rel->r_offset - 3,
				"\x0f\x1f\x40\x00\x64\x8b\x04\x25\0\0\0", 12);
		    }
		}
		rel++;
		rel++;
		goto skip_relocation_and_continue_loop;
	    }

	    if (htab->elf.sgot == NULL)
		{ bfd_set_error (bfd_error_system_error); overall_status = false; break; }

	    bfd_vma off_got = htab->tls_ld_or_ldm_got.offset;
	    if (off_got & 1)
		off_got &= ~1;
	    else
	    {
		Elf_Internal_Rela outrel;

		if (htab->elf.srelgot == NULL)
		{ bfd_set_error (bfd_error_system_error); overall_status = false; break; }

		outrel.r_offset = (htab->elf.sgot->output_section->vma
				+ htab->elf.sgot->output_offset + off_got);

		bfd_put_64 (output_bfd, 0,
			    htab->elf.sgot->contents + off_got);
		bfd_put_64 (output_bfd, 0,
			    htab->elf.sgot->contents + off_got + GOT_ENTRY_SIZE);
		outrel.r_info = htab->r_info (0, R_X86_64_DTPMOD64);
		outrel.r_addend = 0;
		elf_append_rela (output_bfd, htab->elf.srelgot,
					&outrel);
		htab->tls_ld_or_ldm_got.offset |= 1;
	    }
	    relocation_value = htab->elf.sgot->output_section->vma
			    + htab->elf.sgot->output_offset + off_got;
	    unresolved_reloc = false;
	}
	break;

    case R_X86_64_DTPOFF32:
	if (!bfd_link_executable (info)
	    || (input_section->flags & SEC_CODE) == 0)
	    relocation_value -= _bfd_x86_elf_dtpoff_base (info);
	else
	    relocation_value = elf_x86_64_tpoff (info, relocation_value);
	break;

    case R_X86_64_TPOFF32:
    case R_X86_64_TPOFF64:
	BFD_ASSERT (bfd_link_executable (info));
	relocation_value = elf_x86_64_tpoff (info, relocation_value);
	break;

    case R_X86_64_DTPOFF64:
	BFD_ASSERT ((input_section->flags & SEC_CODE) == 0);
	relocation_value -= _bfd_x86_elf_dtpoff_base (info);
	break;

    default:
	break;
    }

    if (!overall_status) break;

    if (unresolved_reloc
	&& !((input_section->flags & SEC_DEBUGGING) != 0
	    && h && h->def_dynamic)
	&& _bfd_elf_section_offset (output_bfd, info, input_section,
				    rel->r_offset) != (bfd_vma) -1)
    {
	switch (r_type)
	{
	case R_X86_64_32S:
	    if ((info->nocopyreloc || eh->def_protected)
		&& !(h->root.u.def.section->flags & SEC_CODE))
	    {
		overall_status = elf_x86_64_need_pic (info, input_bfd, input_section,
							h, NULL, NULL, howto);
		break;
	    }
	    // FALLTHROUGH

	default:
	    _bfd_error_handler (_("%pB(%pA+%#" PRIx64 "): "
				"unresolvable %s relocation against symbol `%s'"),
				input_bfd,
				input_section,
				(uint64_t) rel->r_offset,
				howto->name,
				h->root.root.string);
	    overall_status = false;
	    break;
	}
	if (!overall_status) break;
    }

  do_relocation_label:
    r_status = _bfd_final_link_relocate (howto, input_bfd, input_section,
					  contents, rel->r_offset,
					  relocation_value, rel->r_addend);

  check_relocation_error_label:
    if (r_status != bfd_reloc_ok)
    {
	const char *name;

	if (h != NULL)
	    name = h->root.root.string;
	else
	{
	    name = bfd_elf_string_from_elf_section (input_bfd,
						    symtab_hdr->sh_link,
						    sym->st_name);
	    if (name == NULL) { overall_status = false; break; }
	    if (*name == '\0')
		name = bfd_section_name (sec);
	}

	if (r_status == bfd_reloc_overflow)
	{
	    if (converted_reloc)
	    {
		info->callbacks->einfo
		    ("%X%H:", input_bfd, input_section, rel->r_offset);
		info->callbacks->einfo
		    (_(" failed to convert GOTPCREL relocation against "
		    "'%s'; relink with --no-relax\n"),
		    name);
		overall_status = false;
		break;
	    }
	    (*info->callbacks->reloc_overflow)
		(info, (h ? &h->root : NULL), name, howto->name,
		(bfd_vma) 0, input_bfd, input_section, rel->r_offset);
	}
	else
	{
	    _bfd_error_handler
		(_("%pB(%pA+%#" PRIx64 "): reloc against `%s': error %d"),
		input_bfd, input_section,
		(uint64_t) rel->r_offset, name, (int) r_status);
	    overall_status = false;
	    break;
	}
    }

    *wrel = *rel;
    wrel++;
    rel++;
  skip_relocation_and_continue_loop:; 
}

  if (overall_status && wrel != rel)
    {
      size_t deleted = rel - wrel;

      Elf_Internal_Shdr *rel_hdr = _bfd_elf_single_rel_hdr (input_section->output_section);
      rel_hdr->sh_size -= rel_hdr->sh_entsize * deleted;
      rel_hdr = _bfd_elf_single_rel_hdr (input_section);
      rel_hdr->sh_size -= rel_hdr->sh_entsize * deleted;
      input_section->reloc_count -= deleted;
    }

  return overall_status;
}

/* Finish up dynamic symbol handling.  We set the contents of various
   dynamic sections here.  */

static bool
elf_x86_64_finish_dynamic_symbol (bfd *output_bfd,
				  struct bfd_link_info *info,
				  struct elf_link_hash_entry *h,
				  Elf_Internal_Sym *sym)
{
  struct elf_x86_link_hash_table *htab;
  bool use_plt_second;
  struct elf_x86_link_hash_entry *eh;
  bool local_undefweak;

  htab = elf_x86_hash_table (info, X86_64_ELF_DATA);
  eh = (struct elf_x86_link_hash_entry *) h;

  if (eh->no_finish_dynamic_symbol)
    {
      info->callbacks->fatal (_("%pB: Internal error: `no_finish_dynamic_symbol` flag set for `%s`\n"),
                              output_bfd, h->root.root.string);
      return false;
    }

  use_plt_second = htab->elf.splt != NULL && htab->plt_second != NULL;
  local_undefweak = UNDEFINED_WEAK_RESOLVED_TO_ZERO (info, eh);

  if (h->plt.offset != (bfd_vma) -1)
    {
      bfd_vma got_offset, plt_offset;
      Elf_Internal_Rela rela;
      asection *plt, *gotplt, *relplt, *resolved_plt;
      const struct elf_backend_data *bed;
      bfd_vma plt_got_pcrel_offset;
      bfd_vma plt_index;

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

      if (plt == NULL || gotplt == NULL || relplt == NULL)
        {
          info->callbacks->fatal (_("%pB: Internal error: Missing PLT/GOTPLT/RELPLT section for `%s`\n"),
                                  output_bfd, h->root.root.string);
          return false;
        }

      VERIFY_PLT_ENTRY (info, h, plt, gotplt, relplt, local_undefweak)

      bfd_vma got_offset_index = h->plt.offset / htab->plt.plt_entry_size;
      if (plt == htab->elf.splt)
	{
	  got_offset = (got_offset_index - htab->plt.has_plt0 + 3) * GOT_ENTRY_SIZE;
	}
      else
	{
	  got_offset = got_offset_index * GOT_ENTRY_SIZE;
	}

      memcpy (plt->contents + h->plt.offset, htab->plt.plt_entry,
	      htab->plt.plt_entry_size);

      if (use_plt_second)
	{
	  if (htab->plt_second == NULL || htab->non_lazy_plt == NULL)
            {
              info->callbacks->fatal (_("%pB: Internal error: Missing plt_second or non_lazy_plt for `%s`\n"),
                                      output_bfd, h->root.root.string);
              return false;
            }
	  memcpy (htab->plt_second->contents + eh->plt_second.offset,
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

      plt_got_pcrel_offset = (gotplt->output_section->vma
			      + gotplt->output_offset
			      + got_offset
			      - resolved_plt->output_section->vma
			      - resolved_plt->output_offset
			      - plt_offset
			      - htab->plt.plt_got_insn_size);

      if ((plt_got_pcrel_offset + 0x80000000) > 0xffffffff)
	info->callbacks->fatal (_("%pB: PC-relative offset overflow in PLT entry for `%s`\n"),
				output_bfd, h->root.root.string);

      bfd_put_32 (output_bfd, plt_got_pcrel_offset,
		  (resolved_plt->contents + plt_offset
		   + htab->plt.plt_got_offset));

      if (!local_undefweak)
	{
	  if (htab->plt.has_plt0)
	    bfd_put_64 (output_bfd, (plt->output_section->vma
				     + plt->output_offset
				     + h->plt.offset
				     + htab->lazy_plt->plt_lazy_offset),
			gotplt->contents + got_offset);

	  rela.r_offset = (gotplt->output_section->vma
			   + gotplt->output_offset
			   + got_offset);
	  if (PLT_LOCAL_IFUNC_P (info, h))
	    {
	      if (h->root.u.def.section == NULL)
                {
                  info->callbacks->fatal (_("%pB: Internal error: Local IFUNC symbol `%s` has no definition section\n"),
                                          output_bfd, h->root.root.string);
		  return false;
                }

	      info->callbacks->minfo (_("Local IFUNC function `%s` in %pB\n"),
				      h->root.root.string,
				      h->root.u.def.section->owner);

	      rela.r_info = htab->r_info (0, R_X86_64_IRELATIVE);
	      rela.r_addend = (h->root.u.def.value
			       + h->root.u.def.section->output_section->vma
			       + h->root.u.def.section->output_offset);

	      if (htab->params->report_relative_reloc)
		_bfd_x86_elf_link_report_relative_reloc
		  (info, relplt, h, sym, "R_X86_64_IRELATIVE", &rela);

	      plt_index = htab->next_irelative_index--;
	    }
	  else
	    {
	      rela.r_info = htab->r_info (h->dynindx, R_X86_64_JUMP_SLOT);
	      if (htab->params->mark_plt)
		rela.r_addend = (resolved_plt->output_section->vma
				 + plt_offset
				 + htab->plt.plt_indirect_branch_offset);
	      else
		rela.r_addend = 0;
	      plt_index = htab->next_jump_slot_index++;
	    }

	  if (plt == htab->elf.splt && htab->plt.has_plt0)
	    {
	      bfd_vma plt0_offset
		= h->plt.offset + htab->lazy_plt->plt_plt_insn_end;

	      bfd_put_32 (output_bfd, plt_index,
			  (plt->contents + h->plt.offset
			   + htab->lazy_plt->plt_reloc_offset));

	      if (plt0_offset > 0x80000000)
		info->callbacks->fatal (_("%pB: branch displacement overflow in PLT entry for `%s`\n"),
					output_bfd, h->root.root.string);
	      bfd_put_32 (output_bfd, (bfd_vma) - plt0_offset,
			  (plt->contents + h->plt.offset
			   + htab->lazy_plt->plt_plt_offset));
	    }

	  bed = get_elf_backend_data (output_bfd);
          if (bed == NULL || bed->s == NULL)
            {
              info->callbacks->fatal (_("%pB: Internal error: Missing elf backend data for output BFD\n"), output_bfd);
              return false;
            }

	  bfd_byte *loc = relplt->contents + plt_index * bed->s->sizeof_rela;
	  bed->s->swap_reloca_out (output_bfd, &rela, loc);
	}
    }
  else if (eh->plt_got.offset != (bfd_vma) -1)
    {
      bfd_vma got_offset, plt_offset;
      asection *plt, *got;
      bool got_after_plt;
      int32_t got_pcrel_offset;

      plt = htab->plt_got;
      got = htab->elf.sgot;
      got_offset = h->got.offset;

      if (got_offset == (bfd_vma) -1
	  || (h->type == STT_GNU_IFUNC && h->def_regular)
	  || plt == NULL
	  || got == NULL)
	{
          info->callbacks->fatal (_("%pB: Internal error: Invalid GOT PLT setup for `%s`\n"),
                                  output_bfd, h->root.root.string);
          return false;
        }

      plt_offset = eh->plt_got.offset;
      memcpy (plt->contents + plt_offset,
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
	info->callbacks->fatal (_("%pB: PC-relative offset overflow in GOT PLT entry for `%s`\n"),
				output_bfd, h->root.root.string);

      bfd_put_32 (output_bfd, got_pcrel_offset,
		  (plt->contents + plt_offset
		   + htab->non_lazy_plt->plt_got_offset));
    }

  if (!local_undefweak
      && !h->def_regular
      && (h->plt.offset != (bfd_vma) -1
	  || eh->plt_got.offset != (bfd_vma) -1))
    {
      sym->st_shndx = SHN_UNDEF;
      if (!h->pointer_equality_needed)
	sym->st_value = 0;
    }

  _bfd_x86_elf_link_fixup_ifunc_symbol (info, htab, h, sym);

  if (h->got.offset != (bfd_vma) -1
      && ! GOT_TLS_GD_ANY_P (elf_x86_hash_entry (h)->tls_type)
      && elf_x86_hash_entry (h)->tls_type != GOT_TLS_IE
      && !local_undefweak)
    {
      Elf_Internal_Rela rela;
      asection *relgot = htab->elf.srelgot;
      const char *relative_reloc_name = NULL;
      bool generate_dynamic_reloc = true;
      bool is_glob_dat_case = false;

      if (htab->elf.sgot == NULL)
        {
          info->callbacks->fatal (_("%pB: Internal error: Missing .sgot section for dynamic GOT relocation for `%s`\n"),
                                  output_bfd, h->root.root.string);
          return false;
        }

      rela.r_offset = (htab->elf.sgot->output_section->vma
		       + htab->elf.sgot->output_offset
		       + (h->got.offset &~ (bfd_vma) 1));

      if (h->def_regular && h->type == STT_GNU_IFUNC)
	{
	  if (h->plt.offset == (bfd_vma) -1)
	    {
	      if (htab->elf.splt == NULL)
		{
		  relgot = htab->elf.irelplt;
		}
	      if (SYMBOL_REFERENCES_LOCAL_P (info, h))
		{
		  if (h->root.u.def.section == NULL)
                    {
                      info->callbacks->fatal (_("%pB: Internal error: Local IFUNC symbol `%s` has no definition section\n"),
                                              output_bfd, h->root.root.string);
                      return false;
                    }

		  info->callbacks->minfo (_("Local IFUNC function `%s` in %pB\n"),
					  h->root.root.string,
					  h->root.u.def.section->owner);

		  rela.r_info = htab->r_info (0, R_X86_64_IRELATIVE);
		  rela.r_addend = (h->root.u.def.value
				   + h->root.u.def.section->output_section->vma
				   + h->root.u.def.section->output_offset);
		  relative_reloc_name = "R_X86_64_IRELATIVE";
		}
	      else
		is_glob_dat_case = true;
	    }
	  else if (bfd_link_pic (info))
	    {
	      is_glob_dat_case = true;
	    }
	  else
	    {
	      asection *plt_source;
	      bfd_vma plt_source_offset;

	      if (!h->pointer_equality_needed)
                {
                  info->callbacks->fatal (_("%pB: Internal error: pointer equality not needed for IFUNC symbol `%s`\n"),
                                          output_bfd, h->root.root.string);
                  return false;
                }

	      if (htab->plt_second != NULL)
		{
		  plt_source = htab->plt_second;
		  plt_source_offset = eh->plt_second.offset;
		}
	      else
		{
		  plt_source = htab->elf.splt ? htab->elf.splt : htab->elf.iplt;
		  plt_source_offset =  h->plt.offset;
		}
              if (plt_source == NULL)
                {
                  info->callbacks->fatal (_("%pB: Internal error: PLT source section is NULL for IFUNC symbol `%s`\n"),
                                          output_bfd, h->root.root.string);
                  return false;
                }
	      bfd_put_64 (output_bfd, (plt_source->output_section->vma
				       + plt_source->output_offset
				       + plt_source_offset),
			  htab->elf.sgot->contents + h->got.offset);
	      return true;
	    }
	}
      else if (bfd_link_pic (info)
	       && SYMBOL_REFERENCES_LOCAL_P (info, h))
	{
	  if (!SYMBOL_DEFINED_NON_SHARED_P (h))
	    return false;
	  BFD_ASSERT((h->got.offset & 1) != 0);
	  if (info->enable_dt_relr)
	    generate_dynamic_reloc = false;
	  else
	    {
	      rela.r_info = htab->r_info (0, R_X86_64_RELATIVE);
	      rela.r_addend = (h->root.u.def.value
			       + h->root.u.def.section->output_section->vma
			       + h->root.u.def.section->output_offset);
	      relative_reloc_name = "R_X86_64_RELATIVE";
	    }
	}
      else
	{
	  BFD_ASSERT((h->got.offset & 1) == 0);
	  is_glob_dat_case = true;
	}

      if (is_glob_dat_case)
        {
          bfd_put_64 (output_bfd, (bfd_vma) 0,
                      htab->elf.sgot->contents + h->got.offset);
          rela.r_info = htab->r_info (h->dynindx, R_X86_64_GLOB_DAT);
          rela.r_addend = 0;
        }

      if (generate_dynamic_reloc)
	{
	  if (relgot == NULL || relgot->size == 0)
	    {
	      info->callbacks->fatal (_("%pB: Unable to generate dynamic relocs for `%s` because a suitable section does not exist\n"),
					output_bfd, h->root.root.string);
	      return false;
	    }
	  
	  if (relative_reloc_name != NULL
	      && htab->params->report_relative_reloc)
	    _bfd_x86_elf_link_report_relative_reloc
	      (info, relgot, h, sym, relative_reloc_name, &rela);

	  elf_append_rela (output_bfd, relgot, &rela);
	}
    }

  if (h->needs_copy)
    {
      Elf_Internal_Rela rela;
      asection *s;

      VERIFY_COPY_RELOC (h, htab)

      rela.r_offset = (h->root.u.def.value
		       + h->root.u.def.section->output_section->vma
		       + h->root.u.def.section->output_offset);
      rela.r_info = htab->r_info (h->dynindx, R_X86_64_COPY);
      rela.r_addend = 0;
      if (h->root.u.def.section == htab->elf.sdynrelro)
	s = htab->elf.sreldynrelro;
      else
	s = htab->elf.srelbss;

      if (s == NULL)
        {
          info->callbacks->fatal (_("%pB: Internal error: Missing relocation section for copy relocation of `%s`\n"),
                                  output_bfd, h->root.root.string);
          return false;
        }
      elf_append_rela (output_bfd, s, &rela);
    }

  return true;
}

/* Finish up local dynamic symbol handling.  We set the contents of
   various dynamic sections here.  */

static int
elf_x86_64_finish_local_dynamic_symbol (void **slot, void *inf)
{
  if (inf == NULL)
    return 0;

  struct bfd_link_info *info = (struct bfd_link_info *) inf;

  if (slot == NULL || *slot == NULL)
    return 0;

  struct elf_link_hash_entry *h = (struct elf_link_hash_entry *) *slot;

  return elf_x86_64_finish_dynamic_symbol (info->output_bfd,
					   info, h, NULL);
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

  if (h->root.type == bfd_link_hash_undefweak && h->dynindx == -1)
    {
      return elf_x86_64_finish_dynamic_symbol (info->output_bfd,
					       info, h, NULL);
    }

  return true;
}

/* Used to decide how to sort relocs in an optimal manner for the
   dynamic linker, before writing them out.  */

static enum elf_reloc_type_class
elf_x86_64_reloc_type_class (const struct bfd_link_info *info,
			     const asection *rel_sec ATTRIBUTE_UNUSED,
			     const Elf_Internal_Rela *rela)
{
  bfd *abfd = info->output_bfd;
  const struct elf_backend_data *bed = get_elf_backend_data (abfd);
  struct elf_x86_link_hash_table *htab
    = elf_x86_hash_table (info, X86_64_ELF_DATA);

  if (htab->elf.dynsym != NULL
      && htab->elf.dynsym->contents != NULL)
    {
      unsigned long r_symndx = htab->r_sym (rela->r_info);
      if (r_symndx != STN_UNDEF)
	{
	  Elf_Internal_Sym sym;
	  const bfd_byte *sym_ptr = htab->elf.dynsym->contents
				  + r_symndx * bed->s->sizeof_sym;

	  if (bed->s->swap_symbol_in (abfd, sym_ptr, 0, &sym))
	    {
	      if (ELF_ST_TYPE (sym.st_info) == STT_GNU_IFUNC)
		return reloc_class_ifunc;
	    }
	}
    }

  switch ((int) ELF32_R_TYPE (rela->r_info))
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

/* Finish up the dynamic sections.  */

static bool
elf_x86_64_finish_dynamic_sections (bfd *output_bfd,
				    struct bfd_link_info *info)
{
  struct elf_x86_link_hash_table *htab;

  htab = _bfd_x86_elf_finish_dynamic_sections (output_bfd, info);
  if (htab == NULL)
    return false;

  if (! htab->elf.dynamic_sections_created)
    return true;

  if (htab->elf.splt == NULL || htab->elf.splt->size == 0)
    return true;

  if (bfd_is_abs_section (htab->elf.splt->output_section))
    {
      info->callbacks->fatal
	(_("%P: discarded output section: `%pA'\n"),
	 htab->elf.splt);
      return false;
    }

  elf_section_data (htab->elf.splt->output_section)
    ->this_hdr.sh_entsize = htab->plt.plt_entry_size;

  const bfd_vma splt_base_vma = htab->elf.splt->output_section->vma
                               + htab->elf.splt->output_offset;
  const bfd_vma sgotplt_base_vma = htab->elf.sgotplt->output_section->vma
                                 + htab->elf.sgotplt->output_offset;

  const bfd_vma gotplt_first_entry_offset = 8;
  const bfd_vma gotplt_second_entry_offset = 16;

  if (htab->plt.has_plt0)
    {
      if (htab->lazy_plt == NULL)
        {
          info->callbacks->fatal
            (_("%P: internal error: lazy_plt is NULL when has_plt0 is true\n"));
          return false;
        }

      memcpy (htab->elf.splt->contents,
	      htab->lazy_plt->plt0_entry,
	      htab->lazy_plt->plt0_entry_size);

      const bfd_vma plt0_got1_instruction_len = 6;
      bfd_vma plt0_got1_target_addr = sgotplt_base_vma + gotplt_first_entry_offset;
      bfd_vma plt0_got1_pc_addr = splt_base_vma + plt0_got1_instruction_len;
      bfd_put_32 (output_bfd,
                  plt0_got1_target_addr - plt0_got1_pc_addr,
		  (htab->elf.splt->contents + htab->lazy_plt->plt0_got1_offset));

      bfd_vma plt0_got2_target_addr = sgotplt_base_vma + gotplt_second_entry_offset;
      bfd_vma plt0_got2_pc_addr = splt_base_vma + htab->lazy_plt->plt0_got2_insn_end;
      bfd_put_32 (output_bfd,
                  plt0_got2_target_addr - plt0_got2_pc_addr,
		  (htab->elf.splt->contents + htab->lazy_plt->plt0_got2_offset));
    }

  if (htab->elf.tlsdesc_plt)
    {
      if (htab->lazy_plt == NULL)
        {
          info->callbacks->fatal
            (_("%P: internal error: lazy_plt is NULL when tlsdesc_plt is active\n"));
          return false;
        }

      const bfd_vma sgot_base_vma = htab->elf.sgot->output_section->vma
                                  + htab->elf.sgot->output_offset;

      bfd_put_64 (output_bfd, (bfd_vma) 0,
		  htab->elf.sgot->contents + htab->elf.tlsdesc_got);

      char *tlsdesc_plt_contents_ptr = htab->elf.splt->contents
                                       + htab->elf.tlsdesc_plt;
      memcpy (tlsdesc_plt_contents_ptr,
	      htab->lazy_plt->plt_tlsdesc_entry,
	      htab->lazy_plt->plt_tlsdesc_entry_size);

      bfd_vma tlsdesc_got1_target_addr = sgotplt_base_vma + gotplt_first_entry_offset;
      bfd_vma tlsdesc_got1_pc_addr = splt_base_vma
                                     + htab->elf.tlsdesc_plt
                                     + htab->lazy_plt->plt_tlsdesc_got1_insn_end;
      bfd_put_32 (output_bfd,
                  tlsdesc_got1_target_addr - tlsdesc_got1_pc_addr,
		  (tlsdesc_plt_contents_ptr + htab->lazy_plt->plt_tlsdesc_got1_offset));

      bfd_vma tlsdesc_got2_target_addr = sgot_base_vma + htab->elf.tlsdesc_got;
      bfd_vma tlsdesc_got2_pc_addr = splt_base_vma
                                     + htab->elf.tlsdesc_plt
                                     + htab->lazy_plt->plt_tlsdesc_got2_insn_end;
      bfd_put_32 (output_bfd,
                  tlsdesc_got2_target_addr - tlsdesc_got2_pc_addr,
		  (tlsdesc_plt_contents_ptr + htab->lazy_plt->plt_tlsdesc_got2_offset));
    }

  if (bfd_link_pie (info))
    bfd_hash_traverse (&info->hash->table,
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
  struct elf_x86_link_hash_table *htab = elf_x86_hash_table (info, X86_64_ELF_DATA);
  if (htab == NULL)
    return false;

  /* Fill PLT and GOT entries for local STT_GNU_IFUNC symbols.  */
  if (htab_traverse (htab->loc_hash_table,
		     elf_x86_64_finish_local_dynamic_symbol,
		     info) != 0)
    {
      /* An error occurred during traversal or in the callback.  */
      return false;
    }

  return true;
}

/* Similar to _bfd_elf_get_synthetic_symtab.  Support PLTs with all
   dynamic relocations.   */

static long
elf_x86_64_get_synthetic_symtab (bfd *abfd,
				 long dynsymcount,
				 asymbol **dynsyms,
				 asymbol **ret)
{
  long total_synthetic_sym_count = 0;
  int plt_idx;
  long relsize;
  struct elf_x86_all_plt_layouts all_layouts;

  struct elf_x86_plt plts[] =
    {
      { ".plt", NULL, NULL, plt_unknown, NULL, 0, 0, 0, 0 },
      { ".plt.got", NULL, NULL, plt_unknown, NULL, 0, 0, 0, 0 },
      { ".plt.sec", NULL, NULL, plt_unknown, NULL, 0, 0, 0, 0 },
      { ".plt.bnd", NULL, NULL, plt_unknown, NULL, 0, 0, 0, 0 },
      { NULL, NULL, NULL, plt_unknown, NULL, 0, 0, 0, 0 }
    };

  *ret = NULL;

  if ((abfd->flags & (DYNAMIC | EXEC_P)) == 0)
    return 0;

  if (dynsymcount <= 0)
    return 0;

  relsize = bfd_get_dynamic_reloc_upper_bound (abfd);
  if (relsize <= 0)
    return -1;

  all_layouts.lazy = &elf_x86_64_lazy_plt;
  all_layouts.non_lazy = &elf_x86_64_non_lazy_plt;
  all_layouts.lazy_ibt = &elf_x86_64_lazy_ibt_plt;
  all_layouts.non_lazy_ibt = &elf_x86_64_non_lazy_ibt_plt;

  if (ABI_64_P (abfd))
    {
      all_layouts.lazy_bnd_ibt = &elf_x86_64_lazy_bnd_ibt_plt;
      all_layouts.non_lazy_bnd_ibt = &elf_x86_64_non_lazy_bnd_ibt_plt;
      all_layouts.lazy_bnd = &elf_x86_64_lazy_bnd_plt;
      all_layouts.non_lazy_bnd = &elf_x86_64_non_lazy_bnd_plt;
    }
  else
    {
      all_layouts.lazy_bnd_ibt = NULL;
      all_layouts.non_lazy_bnd_ibt = NULL;
      all_layouts.lazy_bnd = NULL;
      all_layouts.non_lazy_bnd = NULL;
    }

  int sections_successfully_mapped = 0;
  for (plt_idx = 0; plts[plt_idx].name != NULL; plt_idx++)
    {
      asection *plt_section = bfd_get_section_by_name (abfd, plts[plt_idx].name);
      if (plt_section == NULL || plt_section->size == 0
	  || (plt_section->flags & SEC_HAS_CONTENTS) == 0)
	continue;

      plts[plt_idx].sec = plt_section;

      if (!_bfd_elf_mmap_section_contents (abfd, plt_section, &plts[plt_idx].contents))
	{
	  cleanup_plt_mappings(plts, sections_successfully_mapped);
	  return -1;
	}
      sections_successfully_mapped++;

      enum elf_x86_plt_type current_plt_type;
      const void *current_plt_layout_ptr;

      current_plt_type = detect_plt_section_type(plts[plt_idx].contents, plt_section->size,
                                                 &all_layouts, &current_plt_layout_ptr);

      if (current_plt_type == plt_unknown)
	{
	  _bfd_elf_munmap_section_contents (plt_section, plts[plt_idx].contents);
	  plts[plt_idx].contents = NULL;
	  sections_successfully_mapped--;
	  plts[plt_idx].sec = NULL;
	  continue;
	}

      plts[plt_idx].type = current_plt_type;
      plts[plt_idx].plt_layout_ptr = current_plt_layout_ptr;

      long entry_skip_count;
      if ((current_plt_type & plt_lazy))
	{
	  const struct elf_x86_lazy_plt_layout *layout = (const struct elf_x86_lazy_plt_layout *)current_plt_layout_ptr;
	  plts[plt_idx].plt_got_offset = layout->plt_got_offset;
	  plts[plt_idx].plt_got_insn_size = layout->plt_got_insn_size;
	  plts[plt_idx].plt_entry_size = layout->plt_entry_size;
	  entry_skip_count = 1;
	}
      else
	{
	  const struct elf_x86_non_lazy_plt_layout *layout = (const struct elf_x86_non_lazy_plt_layout *)current_plt_layout_ptr;
	  plts[plt_idx].plt_got_offset = layout->plt_got_offset;
	  plts[plt_idx].plt_got_insn_size = layout->plt_got_insn_size;
	  plts[plt_idx].plt_entry_size = layout->plt_entry_size;
	  entry_skip_count = 0;
	}

      if (current_plt_type == (plt_lazy | plt_second))
	plts[plt_idx].count = 0;
      else
	{
	  long n = plt_section->size / plts[plt_idx].plt_entry_size;
	  plts[plt_idx].count = n;
	  total_synthetic_sym_count += n - entry_skip_count;
	}
    }

  long result = _bfd_x86_elf_get_synthetic_symtab (abfd, total_synthetic_sym_count, relsize,
					    (bfd_vma) 0, plts, dynsyms,
					    ret);

  cleanup_plt_mappings(plts, sections_successfully_mapped);

  return result;
}

/* Handle an x86-64 specific section when reading an object file.  This
   is called when elfcode.h finds a section with an unknown type.  */

static bool
elf_x86_64_section_from_shdr (bfd *abfd, Elf_Internal_Shdr *hdr,
			      const char *name, int shindex)
{
  return (hdr->sh_type == SHT_X86_64_UNWIND
          && _bfd_elf_make_section_from_shdr (abfd, hdr, name, shindex));
}

/* Hook called by the linker routine which adds symbols from an object
   file.  We use it to put SHN_X86_64_LCOMMON items in .lbss, instead
   of .bss.  */

static bool
elf_x86_64_add_symbol_hook (bfd *abfd,
			    struct bfd_link_info *info ATTRIBUTE_UNUSED,
			    Elf_Internal_Sym *sym,
			    const char **namep ATTRIBUTE_UNUSED,
			    flagword *flagsp ATTRIBUTE_UNUSED,
			    asection **secp,
			    bfd_vma *valp)
{
  if (sym->st_shndx == SHN_X86_64_LCOMMON)
    {
      asection *lcomm = bfd_get_section_by_name (abfd, "LARGE_COMMON");
      if (lcomm == NULL)
	{
	  lcomm = bfd_make_section_with_flags (abfd,
					       "LARGE_COMMON",
					       (SEC_ALLOC
						| SEC_IS_COMMON
						| SEC_LINKER_CREATED));
	  if (lcomm == NULL)
	    return false;
	  elf_section_flags (lcomm) |= SHF_X86_64_LARGE;
	}
      *secp = lcomm;
      *valp = sym->st_size;
      return true;
    }

  return true;
}


/* Given a BFD section, try to locate the corresponding ELF section
   index.  */

static bool
elf_x86_64_elf_section_from_bfd_section (bfd *abfd ATTRIBUTE_UNUSED,
					 asection *sec, int *index_return)
{
  if (index_return == NULL)
    {
      return false;
    }

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
  const elf_symbol_type *elfsym = (const elf_symbol_type *) asym;

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
  if (sym == NULL)
    {
      return false;
    }
  return (sym->st_shndx == SHN_COMMON
	  || sym->st_shndx == SHN_X86_64_LCOMMON);
}

static unsigned int
elf_x86_64_common_section_index (asection *sec)
{
  if (sec == NULL)
    return SHN_UNDEF;

  if ((elf_section_flags (sec) & SHF_X86_64_LARGE) == 0)
    return SHN_COMMON;
  else
    return SHN_X86_64_LCOMMON;
}

static asection *
elf_x86_64_common_section (asection *sec)
{
  return ((elf_section_flags (sec) & SHF_X86_64_LARGE) == 0)
         ? bfd_com_section_ptr
         : &_bfd_elf_large_com_section;
}

static bool
elf_x86_64_merge_symbol (struct elf_link_hash_entry *h,
			 const Elf_Internal_Sym *sym,
			 asection **psec,
			 bool newdef,
			 bool olddef,
			 bfd *oldbfd,
			 const asection *oldsec)
{
  bool old_symbol_not_defined = !olddef;
  bool hash_entry_is_common_type = (h->root.type == bfd_link_hash_common);
  bool new_symbol_not_defined = !newdef;
  bool psec_points_to_common_section = bfd_is_com_section (*psec);
  bool old_and_new_sections_differ = (oldsec != *psec);

  if (old_symbol_not_defined
      && hash_entry_is_common_type
      && new_symbol_not_defined
      && psec_points_to_common_section
      && old_and_new_sections_differ)
    {
      bool new_sym_is_normal_common_shndx = (sym->st_shndx == SHN_COMMON);
      bool old_sec_has_large_flag = ((elf_section_flags (oldsec) & SHF_X86_64_LARGE) != 0);
      bool new_sym_is_large_common_shndx = (sym->st_shndx == SHN_X86_64_LCOMMON);
      bool old_sec_lacks_large_flag = ((elf_section_flags (oldsec) & SHF_X86_64_LARGE) == 0);

      if (new_sym_is_normal_common_shndx && old_sec_has_large_flag)
	{
	  asection *new_section = bfd_make_section_old_way (oldbfd, "COMMON");
	  if (new_section != NULL)
	    {
	      h->root.u.c.p->section = new_section;
	      h->root.u.c.p->section->flags = SEC_ALLOC;
	    }
	}
      else if (new_sym_is_large_common_shndx && old_sec_lacks_large_flag)
	{
	  *psec = bfd_com_section_ptr;
	}
    }

  return true;
}

static bool
elf_x86_64_section_flags (const Elf_Internal_Shdr *hdr)
{
  if (hdr == NULL)
    {
      return false;
    }

  if (hdr->bfd_section == NULL)
    {
      return false;
    }

  if ((hdr->sh_flags & SHF_X86_64_LARGE) != 0)
    {
      hdr->bfd_section->flags |= SEC_ELF_LARGE;
    }

  return true;
}

static bool
elf_x86_64_fake_sections (bfd *abfd ATTRIBUTE_UNUSED,
			  Elf_Internal_Shdr *hdr, asection *sec)
{
  if (sec->flags & SEC_ELF_LARGE) {
    hdr->sh_flags |= SHF_X86_64_LARGE;
  }

  return true;
}

static bool
elf_x86_64_copy_private_section_data (bfd *ibfd, asection *isec,
				      bfd *obfd, asection *osec,
				      struct bfd_link_info *link_info)
{
  if (!_bfd_elf_copy_private_section_data (ibfd, isec, obfd, osec, link_info))
    {
      return false;
    }

  if (link_info == NULL && ibfd != obfd)
    {
      elf_section_flags (osec) &= ~SHF_X86_64_LARGE;
    }

  return true;
}

static int
check_loadable_section (bfd *abfd, const char *section_name)
{
  asection *s = bfd_get_section_by_name (abfd, section_name);
  return (s != NULL && (s->flags & SEC_LOAD));
}

static int
elf_x86_64_additional_program_headers (bfd *abfd,
				       struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  int count = 0;
  const char * const lrodata_section_name = ".lrodata";
  const char * const ldata_section_name = ".ldata";

  if (check_loadable_section(abfd, lrodata_section_name))
    count++;

  if (check_loadable_section(abfd, ldata_section_name))
    count++;

  return count;
}

/* Return TRUE iff relocations for INPUT are compatible with OUTPUT. */

static bool
elf_x86_64_relocs_compatible (const bfd_target *input,
			      const bfd_target *output)
{
  const elf_backend_data *input_elf_data;
  const elf_backend_data *output_elf_data;
  const elf_backend_info *input_elf_info;
  const elf_backend_info *output_elf_info;

  if (input == NULL || output == NULL)
    return false;

  input_elf_data = xvec_get_elf_backend_data (input);
  output_elf_data = xvec_get_elf_backend_data (output);

  if (input_elf_data == NULL || output_elf_data == NULL)
    return false;

  input_elf_info = input_elf_data->s;
  output_elf_info = output_elf_data->s;

  if (input_elf_info == NULL || output_elf_info == NULL)
    return false;

  if (input_elf_info->elfclass != output_elf_info->elfclass)
    return false;

  return _bfd_elf_relocs_compatible (input, output);
}

/* Set up x86-64 GNU properties.  Return the first relocatable ELF input
   with GNU properties if found.  Otherwise, return NULL.  */

static bfd *
elf_x86_64_link_setup_gnu_properties (struct bfd_link_info *info)
{
  struct elf_x86_init_table init_table = { 0 };
  const struct elf_backend_data *bed;
  struct elf_x86_link_hash_table *htab;

  if ((int) R_X86_64_standard >= (int) R_X86_64_converted_reloc_bit
      || (int) R_X86_64_max <= (int) R_X86_64_converted_reloc_bit
      || ((int) (R_X86_64_GNU_VTINHERIT | R_X86_64_converted_reloc_bit)
	  != (int) R_X86_64_GNU_VTINHERIT)
      || ((int) (R_X86_64_GNU_VTENTRY | R_X86_64_converted_reloc_bit)
	  != (int) R_X86_64_GNU_VTENTRY))
    abort ();

  init_table.plt0_pad_byte = 0x90;

  bed = get_elf_backend_data (info->output_bfd);
  htab = elf_x86_hash_table (info, bed->target_id);
  if (!htab)
    abort ();

  init_table.lazy_plt = &elf_x86_64_lazy_plt;
  init_table.non_lazy_plt = &elf_x86_64_non_lazy_plt;

  init_table.lazy_ibt_plt = &elf_x86_64_lazy_ibt_plt;
  init_table.non_lazy_ibt_plt = &elf_x86_64_non_lazy_ibt_plt;

  if (ABI_64_P (info->output_bfd))
    {
      init_table.sframe_lazy_plt = &elf_x86_64_sframe_plt;
      init_table.sframe_non_lazy_plt = &elf_x86_64_sframe_non_lazy_plt;
      init_table.sframe_lazy_ibt_plt = &elf_x86_64_sframe_ibt_plt;
      init_table.sframe_non_lazy_ibt_plt = &elf_x86_64_sframe_non_lazy_ibt_plt;
    }

  if (ABI_64_P (info->output_bfd))
    {
      init_table.r_info = elf64_r_info;
      init_table.r_sym = elf64_r_sym;
    }
  else
    {
      init_table.r_info = elf32_r_info;
      init_table.r_sym = elf32_r_sym;
    }

  return _bfd_x86_elf_link_setup_gnu_properties (info, &init_table);
}

#define ELF_X86_64_MAX_GLIBC_DEPS 4
#define GLIBC_GNU2_TLS_AUTO_VERSION_TAG_VALUE 2

static void
elf_x86_64_add_glibc_version_dependency
  (struct elf_find_verdep_info *rinfo)
{
  int current_dep_count = 0;
  const char *dependencies[ELF_X86_64_MAX_GLIBC_DEPS] = { NULL };
  bool auto_dependencies[ELF_X86_64_MAX_GLIBC_DEPS] = { false };
  struct elf_x86_link_hash_table *htab;

  if (rinfo->info->enable_dt_relr)
    {
      if (current_dep_count < ELF_X86_64_MAX_GLIBC_DEPS)
        {
          dependencies[current_dep_count] = "GLIBC_ABI_DT_RELR";
          auto_dependencies[current_dep_count] = false;
          current_dep_count++;
        }
    }

  htab = elf_x86_hash_table (rinfo->info, X86_64_ELF_DATA);
  if (htab != NULL)
    {
      if (htab->params->gnu2_tls_version_tag && htab->has_tls_desc_call)
	{
	  if (current_dep_count < ELF_X86_64_MAX_GLIBC_DEPS)
	    {
	      dependencies[current_dep_count] = "GLIBC_ABI_GNU2_TLS";
	      if (htab->params->gnu2_tls_version_tag == GLIBC_GNU2_TLS_AUTO_VERSION_TAG_VALUE)
		auto_dependencies[current_dep_count] = true;
	      current_dep_count++;
	    }
	}
      if (htab->params->mark_plt)
	{
	  if (current_dep_count < ELF_X86_64_MAX_GLIBC_DEPS)
	    {
	      auto_dependencies[current_dep_count] = true;
	      dependencies[current_dep_count] = "GLIBC_ABI_DT_X86_64_PLT";
	      current_dep_count++;
	    }
	}
    }

  if (current_dep_count == 0
      || !_bfd_elf_link_add_glibc_version_dependency (rinfo, dependencies,
						      auto_dependencies))
    return;
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
