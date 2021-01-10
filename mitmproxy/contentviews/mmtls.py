from mitmproxy.utils import strutils
from mitmproxy.coretypes import multidict
from . import base

import itertools

SEP = b'\xf1\x03'

class ViewMMTLS(base.View):
    name = "MMTLS"

    @staticmethod
    def _format_section_content(message, mtype, mlen):
      if mtype == 25:
        if mlen > 36:
          parts = [
            (10, "constant"),
            (32, "random (per cxn)"),
            (2, "??? (5f stays the same)"),
            (2, "sequence number"),
            (29, "constant?"),
          ]
          curr = 0
          for plen, ptype in parts:
            yield from ViewMMTLS._format_hexdump(message[curr:curr+plen])
            curr += plen
            yield from base.format_text("  %d-byte %s" % (plen, ptype))
          yield from ViewMMTLS._format_hexdump(message[curr:])
          yield from base.format_text("  %d-byte %s" % (len(message[curr:]), "changes occasionally -- session ticket"))
        else:
          yield from ViewMMTLS._format_hexdump(message)
      else:
        yield from ViewMMTLS._format_hexdump(message)

    @staticmethod
    def _format_hexdump(data):
      for offset, hexa, s in strutils.hexdump(data):
        yield [
            ("offset", offset + " "),
            ("text", hexa + "   "),
            ("text", s)
        ]

    @staticmethod
    def _format_section(data):
      yield from base.format_text("========SECTION:")
      yield from ViewMMTLS._format_hexdump(data[0:5])
      message_type = data[0]
      assert data[1:3] == SEP
      message_len = int.from_bytes(data[3:5], "big")
      message = data[5:]
      message_type_str = "%d 0x(%02x)"%(message_type, message_type)
      message_len_str = "%d 0x(%04x)"%(message_len, message_len)

      headers = base.format_pairs([("  Section Type", message_type_str), ("  Section Constant", "0xf103"), ("  Section Bytes", message_len_str)])
      yield from headers
      yield from ViewMMTLS._format_section_content(message, message_type, message_len) 
    @staticmethod
    def _format(data):
      sections_raw = data.split(SEP)
      sections = []
      result = ""
      for i in range(1, len(sections_raw)):
        section = sections_raw[i-1][-1:] + SEP +  sections_raw[i]
        if i != len(sections_raw) -1:
          section = section[:-1]
        sections.append(section)
      for section in sections:
        yield from ViewMMTLS._format_section(section)

    def __call__(self, data, **metadata):
        return "MMTLS", self._format(data)
        #return "MMTLS", base.format_pairs([("abcd", "xydfe"), ("1234","4567")])
