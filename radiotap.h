#include "mac.h"

#pragma pack(push, 1)
struct ieee80211_radiotap_header {
	u_int8_t it_version;	/* set to 0 */
	u_int8_t it_pad;
	u_int16_t it_len;		/* entire length */
	u_int32_t it_present;	/* fields present */
};
struct beacon_header {
	uint8_t type;
	uint8_t flag;
	uint16_t duration;	// ms
	Mac da;				// address of destination
	Mac sa;				// address of source
	Mac bssid;
	uint16_t seq;
};
struct fixed_parameter {
	uint64_t timestamp;
	uint16_t interval;
	uint16_t cap_info;
};
struct tagged_parameter {
	uint8_t num;
	uint8_t len;
	uint8_t essid;
};

#pragma pack(pop)