# Guidance page-delivery topic

Read this topic when fetching any guidance document, especially after a clipped or oversized read.
The bounded route is a UTF-8 byte protocol. Its usable `page_size` range is **4 through 16,384
bytes**, inclusive; the default is **4,096 bytes**. Send canonical decimal strings, for example
`"page": "0"` and `"page_size": "4096"`. A request above 16,384 or below 4 is invalid and must
return a field-local correction naming `/page_size`, the permitted range, and the valid retry shape.

When a page is accepted, validate `byte_count` against UTF-8 bytes, `page_offset`, `page_byte_count`,
`page_count`, `total_byte_count`, the source `revision`/`digest`, and the begin/end markers on the
host-visible text where the host requires them. Pages never split a UTF-8 scalar. Carry the exact
`continuation` fields (`uri`, next `page`, same `page_size`, `revision`, and `digest`) into the next
request. A final `complete: true` is only a service-emission fact, not proof of host delivery.

Use `GuidancePageAssembler` for a model-visible reconstruction. Expose the document only after pages
are contiguous, markers and byte counts match, and the final SHA-256 digest matches. If revision or
digest changes, restart at page zero. Do not raise the limit or guess a size after an error; use the
advertised default or a smaller value for a stricter host. See the complete paging contract in
[`request-templates.md`](request-templates.md#reconstruct-a-bounded-guidance-document) and
[`workflow.md`](workflow.md#errors-and-continuations).
