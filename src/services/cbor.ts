export type CborValue =
  | number
  | bigint
  | string
  | boolean
  | null
  | undefined
  | Buffer
  | CborValue[]
  | Map<CborValue, CborValue>;

export class CborError extends Error {}

const MAX_DEPTH = 32;

interface Decoded {
  value: CborValue;
  end: number;
}

const readLength = (
  buf: Buffer,
  offset: number,
  info: number,
): { length: number | bigint; end: number } => {
  if (info < 24) return { length: info, end: offset };
  const need = { 24: 1, 25: 2, 26: 4, 27: 8 }[info];
  if (!need) throw new CborError("Unsupported CBOR length encoding");
  if (offset + need > buf.length) throw new CborError("Truncated CBOR");
  if (need === 1) return { length: buf.readUInt8(offset), end: offset + 1 };
  if (need === 2) return { length: buf.readUInt16BE(offset), end: offset + 2 };
  if (need === 4) return { length: buf.readUInt32BE(offset), end: offset + 4 };
  const big = buf.readBigUInt64BE(offset);
  return {
    length: big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big,
    end: offset + 8,
  };
};

const asSize = (length: number | bigint, available: number): number => {
  if (typeof length === "bigint" || length > available) {
    throw new CborError("Truncated CBOR");
  }
  return length;
};

const decodeAt = (buf: Buffer, offset: number, depth: number): Decoded => {
  if (depth > MAX_DEPTH) throw new CborError("CBOR nested too deeply");
  if (offset >= buf.length) throw new CborError("Truncated CBOR");
  const initial = buf.readUInt8(offset);
  const major = initial >> 5;
  const info = initial & 0x1f;

  if (major === 7) {
    if (info === 20) return { value: false, end: offset + 1 };
    if (info === 21) return { value: true, end: offset + 1 };
    if (info === 22) return { value: null, end: offset + 1 };
    if (info === 23) return { value: undefined, end: offset + 1 };
    if (info === 25 && offset + 3 <= buf.length) {
      const half = buf.readUInt16BE(offset + 1);
      const exponent = (half >> 10) & 0x1f;
      const fraction = half & 0x3ff;
      const sign = half & 0x8000 ? -1 : 1;
      const value =
        exponent === 0
          ? sign * 2 ** -14 * (fraction / 1024)
          : exponent === 31
            ? fraction
              ? Number.NaN
              : sign * Number.POSITIVE_INFINITY
            : sign * 2 ** (exponent - 15) * (1 + fraction / 1024);
      return { value, end: offset + 3 };
    }
    if (info === 26 && offset + 5 <= buf.length) {
      return { value: buf.readFloatBE(offset + 1), end: offset + 5 };
    }
    if (info === 27 && offset + 9 <= buf.length) {
      return { value: buf.readDoubleBE(offset + 1), end: offset + 9 };
    }
    throw new CborError("Unsupported CBOR simple value");
  }

  if (info === 31) throw new CborError("Indefinite-length CBOR is not allowed");
  const { length, end: start } = readLength(buf, offset + 1, info);

  switch (major) {
    case 0:
      return { value: length, end: start };
    case 1:
      return {
        value:
          typeof length === "bigint"
            ? BigInt(-1) - length
            : -1 - (length as number),
        end: start,
      };
    case 2:
    case 3: {
      const size = asSize(length, buf.length - start);
      const bytes = buf.subarray(start, start + size);
      return {
        value: major === 2 ? Buffer.from(bytes) : bytes.toString("utf8"),
        end: start + size,
      };
    }
    case 4: {
      const count = asSize(length, buf.length - start);
      const items: CborValue[] = [];
      let cursor = start;
      for (let i = 0; i < count; i++) {
        const item = decodeAt(buf, cursor, depth + 1);
        items.push(item.value);
        cursor = item.end;
      }
      return { value: items, end: cursor };
    }
    case 5: {
      const count = asSize(length, buf.length - start);
      const map = new Map<CborValue, CborValue>();
      let cursor = start;
      for (let i = 0; i < count; i++) {
        const key = decodeAt(buf, cursor, depth + 1);
        const value = decodeAt(buf, key.end, depth + 1);
        map.set(key.value, value.value);
        cursor = value.end;
      }
      return { value: map, end: cursor };
    }
    default:
      // Major type 6: a tag, which WebAuthn structures do not need; decode the tagged item.
      return decodeAt(buf, start, depth + 1);
  }
};

/** Decodes the first CBOR item in `buf` and returns it with the offset just after it. */
export const decodeCborFirst = (buf: Buffer, offset = 0): Decoded =>
  decodeAt(buf, offset, 0);

/** Decodes a buffer that holds exactly one CBOR item. */
export const decodeCbor = (buf: Buffer): CborValue => {
  const { value, end } = decodeCborFirst(buf);
  if (end !== buf.length) throw new CborError("Trailing bytes after CBOR");
  return value;
};
