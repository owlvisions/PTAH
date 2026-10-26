import {
  MEMBER_REF_PARENT_CODED_INDEX,
  type ManagedMetadataLayout,
} from "./ManagedMetadataLayout.js";
import {
  decodeMetadataCodedIndex,
  metadataRowCursor,
  metadataToken,
} from "./ManagedMetadataHeaps.js";

/** Scalar MemberRef facts; consumers own heap admission and parent diagnostics. */
export const readMemberReferenceRowFacts = (
  bytes: Buffer,
  layout: ManagedMetadataLayout,
  row: number,
) => {
  // Layout admission bounds the complete row independently of its heap values.
  const cursor = metadataRowCursor(bytes, layout, 10, row);
  const parentRaw = cursor.readIndex(layout.codedIndexSize("MemberRefParent"));
  return {
    token: metadataToken(10, row),
    rowOffset: cursor.start,
    parentRaw,
    parent: decodeMetadataCodedIndex(
      parentRaw,
      MEMBER_REF_PARENT_CODED_INDEX.bits,
      MEMBER_REF_PARENT_CODED_INDEX.tables,
      layout.rowCounts,
    ),
    nameIndex: cursor.readIndex(layout.stringIndexSize),
    signatureIndex: cursor.readIndex(layout.blobIndexSize),
  };
};
