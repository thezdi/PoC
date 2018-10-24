// reference : http://newosxbook.com/articles/11208ellpA-II.html

#define BAD_IDENTIFIER	(-1)
#define	ETHER_ADDR_LEN	6
#define	IF_NAMESIZE	16

#define SIOCGA80211 0xC02869C9
#define SIOCSA80211 0x802869C8
#define APPLEGET SIOCGA80211
#define APPLESET SIOCSA80211

struct Apple80211 {
 /* 0x00 */     uint32_t        socket;   // Used for ioctl()
 /* 0x04 */     char            interfaceName[IF_NAMESIZE];
 /* 0x14 */     char            monitored_events_bitmap[0xc];
 /* 0x20 */     uint64_t        monitoring_blob;   // 1ac9: cmpq    $0x0, 0x20(%rbx)
 /* 0x28 */     uint64_t        monitoring_callback;
 /* 0x30 */     uint64_t        monitoring_context;
 /* 0x38 */     uint64_t        binding_handle;
 /* 0x40 */     uint32_t        unknown14;
 /* 0x44 */     uint32_t        unknown15;
 /* 0x48 */     uint64_t        used_for_monitoring2;  // 1ad0: cmpq    $0x0, 0x48(%rbx)
};

typedef struct Apple80211 *Apple80211Ref;

struct apple80211_ioctl_str {
    char ifname[16];
    uint32_t  type;
    uint32_t  unknown;
    uint32_t  length;
    void     *data;
};