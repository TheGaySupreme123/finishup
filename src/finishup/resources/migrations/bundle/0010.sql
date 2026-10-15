PRAGMA application_id = 0x594F4554;

-- Migration 0010 adds the second, explicit consent arm for native-host
-- ordinary-work content.  Existing structural grants remain contentless
-- ([]) until the user enables a versioned profile.
ALTER TABLE observation_consent ADD COLUMN content_capture_profiles_json TEXT NOT NULL DEFAULT '[]'
    CHECK (
        length(content_capture_profiles_json) <= 512
    );

PRAGMA user_version = 10;
