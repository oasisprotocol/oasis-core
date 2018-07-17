pragma solidity ^0.4.23;

/**
 * @dev library for parsing CBOR encoded data.
 */
library CBOR {
    uint8 private constant MAJOR_TYPE_INT = 0;
    uint8 private constant MAJOR_TYPE_NEGATIVE_INT = 1;
    uint8 private constant MAJOR_TYPE_BYTES = 2;
    uint8 private constant MAJOR_TYPE_STRING = 3;
    uint8 private constant MAJOR_TYPE_ARRAY = 4;
    uint8 private constant MAJOR_TYPE_MAP = 5;
    uint8 private constant MAJOR_TYPE_CONTENT_FREE = 7;

    /**
     * @dev Given a pointer into a buffer of memory, return the pointer of the
     * next encoded item.
     */
    function toNext(byte[] memory buf, uint ptr) private pure returns (uint) {
        uint8 major_type;
        uint8 extrainfo;
        uint b;
        uint l;
        (major_type, extrainfo) = decodeType(buf[ptr]);
        if(major_type == MAJOR_TYPE_INT || major_type == MAJOR_TYPE_NEGATIVE_INT) {
            (, b) = decodeInt(buf, ptr, extrainfo);
            return ptr + 1 + b;
        } else if (major_type == MAJOR_TYPE_BYTES || major_type == MAJOR_TYPE_STRING) {
            (l, b) = decodeInt(buf, ptr, extrainfo);
            return ptr + 1 + b + l;
        } else if (major_type == MAJOR_TYPE_ARRAY || major_type == MAJOR_TYPE_MAP) {
            (l, b) = decodeInt(buf, ptr, extrainfo);
            if (major_type == MAJOR_TYPE_MAP) {
                l *= 2;
            }
            while (l-- > 0) {
                b += toNext(buf, ptr + 1 + b);
            }
            return ptr + 1 + b;
        }
        // TODO: type 6 - optional tagging of custom types.
        // TODO: type 7 - floating point numbers.
    }

    /**
     * @dev Split a CBOR type into the major and extra_info fields.
     */
    function decodeType(byte buf) private pure returns (uint8, uint8) {
        return (uint8(buf >> 5), uint8(buf & 31));
    }

    /**
     * @dev Perform the standard CBOR extraction for numeric types.
     * Given a pointer to the type definition, and extra_info of the low order
     * bits from that byte, returns a tuple of (the number n, the number of bytes
     * used to represented that number).
     */
    function decodeInt(byte[] memory buf, uint ptr, uint8 info) private pure returns (uint, uint) {
        if(info <= 23) {
            return (info, 0);
        } else if (info == 24) {
            return (uint8(buf[ptr + 1]), 1);
        } else if (info == 25) {
            return (uint16(buf[ptr + 1]) << 8 | uint16(buf[ptr + 2]), 2);
        } else if (info == 26) {
            return (uint32(buf[ptr + 1]) << 24 | uint32(buf[ptr + 2]) << 16 |
                    uint32(buf[ptr + 3]) << 8 | uint32(buf[ptr + 4]), 4);
        } else if (info == 27) {
            return (uint64(buf[ptr + 1]) << 56 | uint64(buf[ptr + 2]) << 48 |
                    uint64(buf[ptr + 3]) << 40 | uint64(buf[ptr + 4]) << 32 |
                    uint64(buf[ptr + 5]) << 24 | uint64(buf[ptr + 6]) << 16 |
                    uint64(buf[ptr + 7]) << 8 | uint64(buf[ptr + 8]), 8);
        }
    }

    /**
     * @dev Check if the cbor value at a given offset in a buffer matches the
     * byte sequence `key`.
     */
    function matches(byte[] memory buf, uint ptr, bytes memory key) private pure returns (bool) {
        uint l = key.length;
        while(l-- > 0) {
            if(buf[ptr + l - 1] != key[l - 1]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Given a cbor (buf, ptr) to a map, provide the offest of the value in the
     * map where the associated key in the map `matches` the provided key.
     */
    function getItemForKey(byte[] memory buf,  uint ptr, bytes memory key) public pure returns (uint) {
        uint8 major_type;
        uint8 info;
        uint numkeys;
        uint prefix_bytes;
        (major_type, info) = decodeType(buf[ptr]);
        require(major_type == MAJOR_TYPE_MAP);
        (numkeys, prefix_bytes) = decodeInt(buf, ptr, info);
        prefix_bytes = prefix_bytes + 1 + ptr;
        while (numkeys-- > 0) {
            if (matches(buf, prefix_bytes, key)) {
                prefix_bytes += toNext(buf, prefix_bytes);
                return prefix_bytes;
            } else {
                prefix_bytes += toNext(buf, prefix_bytes);
                prefix_bytes += toNext(buf, prefix_bytes);
            }
        }
    }

    /**
     * @dev Read an array definition to get (the pointer to the first item, and
     * number of items).
     */
    function readArray(byte[] memory buf, uint ptr) public pure returns (uint, uint) {
        uint8 major_type;
        uint8 extrainfo;
        uint b;
        uint l;
        (major_type, extrainfo) = decodeType(buf[ptr]);
        require(major_type == MAJOR_TYPE_ARRAY);
        (l, b) = decodeInt(buf, ptr, extrainfo);
        return (ptr + 1 + b, l);
    }

    /**
     * @dev Read a data definition as an address. requires the length is
     * compatible.
     * // addresses are 20bytes, so expect the header is 1 byte.
     */
    function readAddress(byte[] memory buf, uint ptr) public pure returns(address) {
        uint160 out;
        for (uint8 i = 0; i < 20; i++) {
            out += uint160(buf[ptr + 1 + i]) << uint32(32 * i);
        }
        return address(out);
    }
}
