/* photoid.c - photo ID handling code
 * Copyright (C) 2001, 2002, 2005, 2006, 2008 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* Returns 0 for error, 1 for valid */
function parse_image_header(attr, len)
{
  var headerlen;

  if(attr.len<3)
    return 0;

  /* For historical reasons (i.e. "oops!"), the header length is
     little endian. */
  headerlen=(attr.data[1]<<8) | attr.data[0];

  if(headerlen>attr.len)
    return 0;

  if(attr.len>=4)
  {
    if(attr.data[2]==1) /* header version 1 */
	    attr.type=attr.data[3];
    else
	    attrtype=0;
  }
  len=attr.len-headerlen;

  if(len==0)
    return 0;

  return 1;
}

/* style==0 for extension, 1 for name, 2 for MIME type.  Remember that
   the "name" style string could be used in a user ID name field, so
   make sure it is not too big (see parse-packet.c:parse_attribute).
   Extensions should be 3 characters long for the best cross-platform
   compatibility. */
function image_type_to_string(type, style)
{
  var string;

  switch(type)
  {
    case 1: /* jpeg */
      if(style==0)
	      string="jpg";
      else if(style==1)
	      string="jpeg";
      else
	      string="image/jpeg";
      break;

    default:
      if(style==0)
	      string="bin";
      else if(style==1)
	      string="unknown";
      else
	      string="image/x-unknown";
      break;
    }

  return string;
}

exports.parse_image_header = parse_image_header; 
exports.image_type_to_string = image_type_to_string; 
