PRAGMA application_id = 0x594F4554;

-- Migration 0013 retains bounded provider usage for every physical semantic attempt (issue #715).
-- These are structural counters only: no provider response, account identity, prompt, or secret is
-- written to the task ledger. Legacy attempts remain NULL until a new provider result is observed.
ALTER TABLE semantic_attempts ADD COLUMN usage_input_tokens INTEGER CHECK (
    usage_input_tokens IS NULL OR usage_input_tokens BETWEEN 0 AND 9007199254740991
);
ALTER TABLE semantic_attempts ADD COLUMN usage_cached_input_tokens INTEGER CHECK (
    usage_cached_input_tokens IS NULL OR usage_cached_input_tokens BETWEEN 0 AND 9007199254740991
);
ALTER TABLE semantic_attempts ADD COLUMN usage_cache_write_input_tokens INTEGER CHECK (
    usage_cache_write_input_tokens IS NULL OR usage_cache_write_input_tokens BETWEEN 0 AND 9007199254740991
);
ALTER TABLE semantic_attempts ADD COLUMN usage_output_tokens INTEGER CHECK (
    usage_output_tokens IS NULL OR usage_output_tokens BETWEEN 0 AND 9007199254740991
);
ALTER TABLE semantic_attempts ADD COLUMN usage_reasoning_output_tokens INTEGER CHECK (
    usage_reasoning_output_tokens IS NULL OR usage_reasoning_output_tokens BETWEEN 0 AND 9007199254740991
);
ALTER TABLE semantic_attempts ADD COLUMN usage_total_tokens INTEGER CHECK (
    (usage_total_tokens IS NULL
        AND usage_input_tokens IS NULL
        AND usage_cached_input_tokens IS NULL
        AND usage_cache_write_input_tokens IS NULL
        AND usage_output_tokens IS NULL
        AND usage_reasoning_output_tokens IS NULL)
    OR
    (usage_total_tokens IS NOT NULL
        AND usage_total_tokens BETWEEN 0 AND 9007199254740991
        AND state <> 'started'
        AND usage_input_tokens IS NOT NULL
        AND usage_cached_input_tokens IS NOT NULL
        AND usage_cache_write_input_tokens IS NOT NULL
        AND usage_output_tokens IS NOT NULL
        AND usage_reasoning_output_tokens IS NOT NULL
        AND usage_cached_input_tokens <= usage_input_tokens
        AND usage_reasoning_output_tokens <= usage_output_tokens
        AND usage_input_tokens + usage_output_tokens = usage_total_tokens)
);

-- The six fields are one atomic usage sample.  The final-column check above makes a partial
-- non-null sample invalid; replay also validates the all-null legacy case before constructing the
-- typed value.

PRAGMA user_version = 13;
