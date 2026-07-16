# First memory lifecycle

The lifecycle is evidence → proposal → review → approved write → immutable version. Create a proposal with evidence IDs, inspect it, approve or reject it, write only after approval, and read the stored version back.

A revision creates another version. Tombstone makes a memory inactive without erasing history. Rollback selects an earlier immutable version and emits audit state. Proposal creation never implies promotion.
