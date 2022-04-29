/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<8> TYPE_TCP = 6;
const bit<8> TYPE_UDP = 17;
const bit<16> ENTRY_SIZE = 2;

const bit<8> PKT_TYPE_NORMAL           = 1;
const bit<8> PKT_TYPE_RESUBMIT         = 2;
const bit<8> PKT_TYPE_MIRROR_NORMAL    = 3;
const bit<8> PKT_TYPE_MIRROR_ABNORMAL  = 4;

#define PACKET_STATS_INDEX_WIDTH		5 
#define PACKET_STATS_SIZE				1<<PACKET_STATS_INDEX_WIDTH
typedef bit<PACKET_STATS_INDEX_WIDTH>	tocpu_stats_index_t;
/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header ports_h {
    bit<16>  src_port;
    bit<16>  dst_port;
}

header common_header_h {
    bit<8>   type;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
    /***********************  H E A D E R S  ************************/
header to_cpu_h {
    bit<8>   pkg_num;
    bit<16>  total_len;
    bit<8>   pkg_num2;
    bit<16>  total_len2;
}

header ing_port_mirror_h {
	bit<8>   type;
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
    bit<8>    pkg_num;
    bit<16>   total_len;
    bit<8>    pkg_num2;
    bit<16>   total_len2;
}

struct my_ingress_headers_t {
    common_header_h common;
    ethernet_h 		cpu_ethernet;
    to_cpu_h		to_cpu;
    ethernet_h      ethernet;
    ipv4_h          ipv4;
    ports_h         ports;
}

// Limit to 64bit
header resubmit_t {
    bit<16> action_flag;  
    bit<16> total_len;
    bit<16> total_len2;
    bit<16> pkg_num_all;
}


    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/
#define HASH_KEY_SIZE 		 16

#define BIT_PKG_NUM2    0x1
#define BIT_TIMEOUT2    0x2
#define BIT_EMPTY2      0x4
#define BIT_PKG_NUM     0x8
#define BIT_TIMEOUT     0x10
#define BIT_SRC_ADDR    0x20
#define BIT_DST_ADDR    0x40
#define BIT_PROTOCOL    0x80
#define BIT_SRC_PORT    0x100
#define BIT_DST_PORT    0x200
#define BIT_EMPTY       0x400


struct my_ingress_metadata_t {
    resubmit_t         resubmit_data;
    bit<16>            action_flag;
    bit<32>            srcip;
//    bit<32>            srcip2;
    bit<32>            dstip;
//    bit<32>            dstip2;
    bit<16>            srcport;
//    bit<16>            srcport2;
    bit<16>            dstport;
//    bit<16>            dstport2;
    bit<8>             protocol;
//    bit<8>             protocol2;
    bit<16>            total_len;
    bit<16>            total_len2;
    bit<16>            total_len_writeback;
    bit<16>            total_len2_writeback;
    bit<8>             pkg_num;
    bit<8>             pkg_num2;
    bit<8>             pkg_num_writeback;
    bit<8>             pkg_num2_writeback;
    bit<32>            hashout_send;
    bit<32>            hashout_rece;
    bit<HASH_KEY_SIZE> index;
    bit<HASH_KEY_SIZE> index2;
    bit<32>            tstamp;
    bit<32>            tstamp_interval;
    bit<32>            tstamp_interval2;
    bit<1>             first_stream_end_flag;
    bit<1>             first_add_flag;
    bit<1>             first_update_flag;
    bit<1>             first_clear_flag;
    bit<1>             second_stream_end_flag;
    bit<1>             second_add_flag;
    bit<1>             second_update_flag;
    bit<1>             second_clear_flag;
    bit<32>              subsip;
    bit<32>              subdip;
    bit<16>              subsport;
    bit<16>              subdport;
    bit<8>               subprotocol;
    bit<32>              subsip2;
    bit<32>              subdip2;
    bit<16>              subsport2;
    bit<16>              subdport2;
    bit<8>				mirror_type;
    bit<10>				mirror_session;
    
}


    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in                         pkt,
                     /* User */    
                     out my_ingress_headers_t          hdr,
                     out my_ingress_metadata_t         meta,
                     /* Intrinsic */
                     out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
     state start {
        meta = {{0, 0, 0, 0}, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag){
            1: parse_resubmit;
            0: parse_normal;
        }
    }
    
    state parse_resubmit {
        pkt.extract(meta.resubmit_data);
        meta.action_flag =  meta.resubmit_data.action_flag;
        meta.pkg_num = meta.resubmit_data.pkg_num_all[7:0];
        meta.total_len = meta.resubmit_data.total_len;
        meta.pkg_num2 = meta.resubmit_data.pkg_num_all[15:8];
        meta.total_len2 = meta.resubmit_data.total_len2;
        meta.mirror_session = 1;
        meta.mirror_type = 1;
        transition parse_ethernet;
    }
    
    state parse_normal {
        pkt.advance(PORT_METADATA_SIZE);
        meta.resubmit_data.action_flag = 0;
        transition parse_ethernet;
   }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            default: reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_ports;
            TYPE_UDP: parse_ports;
            default: reject;
        }
    }

    state parse_ports {
        pkt.extract(hdr.ports);
        transition accept;
    }

}

    /***************** M A T C H - A C T I O N  *********************/
control IngressAI(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
	tocpu_stats_index_t packet_dir_index = 0;
	Counter<bit<64>, tocpu_stats_index_t>(PACKET_STATS_SIZE, CounterType_t.PACKETS) packet_dir_stats;
	tocpu_stats_index_t ai_dect_index = 0;
	Counter<bit<64>, tocpu_stats_index_t>(PACKET_STATS_SIZE, CounterType_t.PACKETS) ai_dect_stats;
/* basic actions used in the following process */
    action drop(){
        ig_dprsr_md.drop_ctl = 0x1; // Drop packet.
        exit;
    }
    action set_submit(){
        ig_dprsr_md.resubmit_type = 0x2; // Drop packet.
        meta.resubmit_data.pkg_num_all[7:0] = meta.pkg_num;
        meta.resubmit_data.total_len = meta.total_len;
        meta.resubmit_data.pkg_num_all[15:8] = meta.pkg_num2;
        meta.resubmit_data.total_len2 = meta.total_len2;
    }
    
	action action_set_current_tstamp(){
		meta.resubmit_data.action_flag = 0x8000;
		meta.tstamp = ig_intr_md.ingress_mac_tstamp[47:16];
	}
	
	table set_current_tstamp{
		actions={
			action_set_current_tstamp;
		}
	}

    
    // Define hash bucket register
// First srcip    ----------------------------
    const bit<32> ai_character_table_size = 1 << HASH_KEY_SIZE;
    Register<bit<32>, bit<HASH_KEY_SIZE>>(ai_character_table_size)  hash_first_bucket_srcip;
    RegisterAction<bit<32>, bit<HASH_KEY_SIZE>, bit<32>>(hash_first_bucket_srcip) put_first_bucket_srcip_action = {
        void apply(inout bit<32> value, out bit<32> return_value) {
            return_value = value;
            value = hdr.ipv4.src_addr;
        }
    };
    RegisterAction<bit<32>, bit<HASH_KEY_SIZE>, bit<32>>(hash_first_bucket_srcip) get_first_bucket_srcip_action = {
        void apply(inout bit<32> value, out bit<32> return_value) {
            return_value = value;
        }
    };
    
    action first_bucket_srcip_put_action(){
        put_first_bucket_srcip_action.execute(meta.index);
    }    
    action first_bucket_srcip_get_action(){
        meta.srcip = get_first_bucket_srcip_action.execute(meta.index);
        meta.subsip = meta.srcip ^ hdr.ipv4.src_addr;
        meta.subsip2 = meta.srcip ^ hdr.ipv4.dst_addr;
    }
    
// First dstip   ----------------------------
    Register<bit<32>, bit<HASH_KEY_SIZE>>(ai_character_table_size)  hash_first_bucket_dstip;
    RegisterAction<bit<32>, bit<HASH_KEY_SIZE>, bit<32>>(hash_first_bucket_dstip) put_first_bucket_dstip_action = {
        void apply(inout bit<32> value, out bit<32> return_value) {
            return_value = value;
            value = hdr.ipv4.src_addr;
        }
    };
    RegisterAction<bit<32>, bit<HASH_KEY_SIZE>, bit<32>>(hash_first_bucket_dstip) get_first_bucket_dstip_action = {
        void apply(inout bit<32> value, out bit<32> return_value) {
            return_value = value;
        }
    };
    
    action first_bucket_dstip_put_action(){
        put_first_bucket_dstip_action.execute(meta.index);
    }    
    action first_bucket_dstip_get_action(){
        meta.dstip = get_first_bucket_dstip_action.execute(meta.index);
        meta.subdip = meta.dstip ^ hdr.ipv4.dst_addr;
        meta.subdip2 = meta.dstip ^ hdr.ipv4.src_addr;
    }
    
// First srcport    ----------------------------
    Register<bit<16>, bit<HASH_KEY_SIZE>>(ai_character_table_size)  hash_first_bucket_srcport;
    RegisterAction<bit<16>, bit<HASH_KEY_SIZE>, bit<16>>(hash_first_bucket_srcport) put_first_bucket_srcport_action = {
        void apply(inout bit<16> value, out bit<16> return_value) {
            return_value = value;
            value = hdr.ports.src_port;
        }
    };
    RegisterAction<bit<16>, bit<HASH_KEY_SIZE>, bit<16>>(hash_first_bucket_srcport) get_first_bucket_srcport_action = {
        void apply(inout bit<16> value, out bit<16> return_value) {
            return_value = value;
        }
    };
    
    action first_bucket_srcport_put_action(){
        put_first_bucket_srcport_action.execute(meta.index);
    }    
    action first_bucket_srcport_get_action(){
        meta.srcport = get_first_bucket_srcport_action.execute(meta.index);
        meta.subsport = meta.srcport ^ hdr.ports.src_port;
        meta.subsport2 = meta.srcport ^ hdr.ports.dst_port;
    }
    
// First dstport    ----------------------------
    Register<bit<16>, bit<HASH_KEY_SIZE>>(ai_character_table_size)  hash_first_bucket_dstport;
    RegisterAction<bit<16>, bit<HASH_KEY_SIZE>, bit<16>>(hash_first_bucket_dstport) put_first_bucket_dstport_action = {
        void apply(inout bit<16> value, out bit<16> return_value) {
            return_value = value;
            value = hdr.ports.dst_port;
        }
    };
    RegisterAction<bit<16>, bit<HASH_KEY_SIZE>, bit<16>>(hash_first_bucket_dstport) get_first_bucket_dstport_action = {
        void apply(inout bit<16> value, out bit<16> return_value) {
            return_value = value;
        }
    };

    action first_bucket_dstport_put_action(){
        put_first_bucket_dstport_action.execute(meta.index);
    }
    action first_bucket_dstport_get_action(){
        meta.dstport = get_first_bucket_dstport_action.execute(meta.index);
        meta.subdport = meta.dstport ^ hdr.ports.dst_port;
        meta.subdport2 = meta.dstport ^ hdr.ports.src_port;
    }
    
// First protocol    ----------------------------
    Register<bit<8>, bit<HASH_KEY_SIZE>>(ai_character_table_size)  hash_first_bucket_protocol;
    RegisterAction<bit<8>, bit<HASH_KEY_SIZE>, bit<8>>(hash_first_bucket_protocol) put_first_bucket_protocol_action = {
        void apply(inout bit<8> value, out bit<8> return_value) {
            return_value = value;
            value = hdr.ipv4.protocol;
        }
    };
    RegisterAction<bit<8>, bit<HASH_KEY_SIZE>, bit<8>>(hash_first_bucket_protocol) get_first_bucket_protocol_action = {
        void apply(inout bit<8> value, out bit<8> return_value) {
            return_value = value;
        }
    };
    
    action first_bucket_protocol_put_action(){
        put_first_bucket_protocol_action.execute(meta.index);
    }    
    action first_bucket_protocol_get_action(){
        meta.protocol = get_first_bucket_protocol_action.execute(meta.index);
        meta.subprotocol = meta.protocol ^ hdr.ipv4.protocol;
    }
    
// First pkgnum    ----------------------------
    Register<bit<8>, bit<HASH_KEY_SIZE>>(ai_character_table_size)  hash_first_bucket_pkgnum;
    RegisterAction<bit<8>, bit<HASH_KEY_SIZE>, bit<8>>(hash_first_bucket_pkgnum) put_first_bucket_pkgnum_action = {
        void apply(inout bit<8> value, out bit<8> return_value) {
            return_value = value;
            value = meta.pkg_num_writeback;
        }
    };
    RegisterAction<bit<8>, bit<HASH_KEY_SIZE>, bit<8>>(hash_first_bucket_pkgnum) get_first_bucket_pkgnum_action = {
        void apply(inout bit<8> value, out bit<8> return_value) {
            return_value = value;
        }
    };
    RegisterAction<bit<8>, bit<HASH_KEY_SIZE>, bit<8>>(hash_first_bucket_pkgnum) clear_first_bucket_pkgnum_action = {
        void apply(inout bit<8> value, out bit<8> return_value) {
            return_value = value;
            if(meta.first_update_flag == 1){
                value = value - 1;
            }else{
                value = 0;
            }
        }
    };

    action first_bucket_pkgnum_put_action(){
        meta.pkg_num = put_first_bucket_pkgnum_action.execute(meta.index);
    }
    action first_bucket_pkgnum_get_action(){
        meta.pkg_num = get_first_bucket_pkgnum_action.execute(meta.index);
    }
    action first_bucket_pkgnum_clear_action(){
        meta.pkg_num = clear_first_bucket_pkgnum_action.execute(meta.index);
    }
    
// First totallen    ----------------------------
    Register<bit<16>, bit<HASH_KEY_SIZE>>(ai_character_table_size)  hash_first_bucket_totallen;
    RegisterAction<bit<16>, bit<HASH_KEY_SIZE>, bit<16>>(hash_first_bucket_totallen) put_first_bucket_totallen_action = {
        void apply(inout bit<16> value, out bit<16> return_value) {
            return_value = value;
            value = meta.total_len_writeback;
        }
    };
    RegisterAction<bit<16>, bit<HASH_KEY_SIZE>, bit<16>>(hash_first_bucket_totallen) get_first_bucket_totallen_action = {
        void apply(inout bit<16> value, out bit<16> return_value) {
            return_value = value;
        }
    };
    RegisterAction<bit<16>, bit<HASH_KEY_SIZE>, bit<16>>(hash_first_bucket_totallen) clear_first_bucket_totallen_action = {
        void apply(inout bit<16> value, out bit<16> return_value) {
            return_value = value;
            if(meta.first_update_flag == 1){
                value = value - hdr.ipv4.total_len;
            }else{
                value = 0;
            }
        }
    };

    action first_bucket_totallen_put_action(){
        meta.total_len = put_first_bucket_totallen_action.execute(meta.index);
    }
    action first_bucket_totallen_get_action(){
        meta.total_len = get_first_bucket_totallen_action.execute(meta.index);
    }
    action first_bucket_totallen_clear_action(){
        meta.total_len = clear_first_bucket_totallen_action.execute(meta.index);
    }
    
// First tstamp    ----------------------------    
    Register<bit<32>, bit<HASH_KEY_SIZE>>(ai_character_table_size)  hash_first_bucket_tstamp;
    RegisterAction<bit<32>, bit<HASH_KEY_SIZE>, bit<32>>(hash_first_bucket_tstamp) put_first_bucket_tstamp_action = {
        void apply(inout bit<32> value, out bit<32> return_value) {
            return_value = value;
            value = ig_intr_md.ingress_mac_tstamp[47:16];
        }
    };
    RegisterAction<bit<32>, bit<HASH_KEY_SIZE>, bit<32>>(hash_first_bucket_tstamp) get_first_bucket_tstamp_action = {
        void apply(inout bit<32> value, out bit<32> return_value) {
            return_value = meta.tstamp - value;
        }
    };

    action first_bucket_tstamp_put_action(){
        put_first_bucket_tstamp_action.execute(meta.index);
    }
    action first_bucket_tstamp_get_action(){
        meta.tstamp_interval = get_first_bucket_tstamp_action.execute(meta.index);
    }
    
// Second srcip    ----------------------------    
    Register<bit<32>, bit<HASH_KEY_SIZE>>(ai_character_table_size)  hash_second_bucket_srcip;
    RegisterAction<bit<32>, bit<HASH_KEY_SIZE>, bit<32>>(hash_second_bucket_srcip) put_second_bucket_srcip_action = {
        void apply(inout bit<32> value, out bit<32> return_value) {
            return_value = value;
            value = hdr.ipv4.src_addr;
        }
    };
    RegisterAction<bit<32>, bit<HASH_KEY_SIZE>, bit<32>>(hash_second_bucket_srcip) get_second_bucket_srcip_action = {
        void apply(inout bit<32> value, out bit<32> return_value) {
            return_value = value;
        }
    };
    action second_bucket_srcip_put_action(){
        put_second_bucket_srcip_action.execute(meta.index2);
    } 
//    action second_bucket_srcip_get_action(){
//        meta.srcip2 = get_second_bucket_srcip_action.execute(meta.index2);
//    }
    
// Second dstip    ----------------------------        
    Register<bit<32>, bit<HASH_KEY_SIZE>>(ai_character_table_size)  hash_second_bucket_dstip;
    RegisterAction<bit<32>, bit<HASH_KEY_SIZE>, bit<32>>(hash_second_bucket_dstip) put_second_bucket_dstip_action = {
        void apply(inout bit<32> value, out bit<32> return_value) {
            return_value = value;
            value = hdr.ipv4.src_addr;
        }
    };
    RegisterAction<bit<32>, bit<HASH_KEY_SIZE>, bit<32>>(hash_second_bucket_dstip) get_second_bucket_dstip_action = {
        void apply(inout bit<32> value, out bit<32> return_value) {
            return_value = value;
        }
    };

    action second_bucket_dstip_put_action(){
        put_second_bucket_dstip_action.execute(meta.index2);
    }
//    action second_bucket_dstip_get_action(){
//        meta.dstip2 = get_second_bucket_dstip_action.execute(meta.index2);
//    }
    
// Second srcport    ----------------------------       
    Register<bit<16>, bit<HASH_KEY_SIZE>>(ai_character_table_size)  hash_second_bucket_srcport;
    RegisterAction<bit<16>, bit<HASH_KEY_SIZE>, bit<16>>(hash_second_bucket_srcport) put_second_bucket_srcport_action = {
        void apply(inout bit<16> value, out bit<16> return_value) {
            return_value = value;
            value = hdr.ports.src_port;
        }
    };
    RegisterAction<bit<16>, bit<HASH_KEY_SIZE>, bit<16>>(hash_second_bucket_srcport) get_second_bucket_srcport_action = {
        void apply(inout bit<16> value, out bit<16> return_value) {
            return_value = value;
        }
    };
    
    action second_bucket_srcport_put_action(){
        put_second_bucket_srcport_action.execute(meta.index2);
    }  
//    action second_bucket_srcport_get_action(){
//        meta.srcport2 = get_second_bucket_srcport_action.execute(meta.index2);
//    }

// Second dstport    ----------------------------   
    Register<bit<16>, bit<HASH_KEY_SIZE>>(ai_character_table_size)  hash_second_bucket_dstport;
    RegisterAction<bit<16>, bit<HASH_KEY_SIZE>, bit<16>>(hash_second_bucket_dstport) put_second_bucket_dstport_action = {
        void apply(inout bit<16> value, out bit<16> return_value) {
            return_value = value;
            value = hdr.ports.dst_port;
        }
    };
    RegisterAction<bit<16>, bit<HASH_KEY_SIZE>, bit<16>>(hash_second_bucket_dstport) get_second_bucket_dstport_action = {
        void apply(inout bit<16> value, out bit<16> return_value) {
            return_value = value;
        }
    };

    action second_bucket_dstport_put_action(){
        put_second_bucket_dstport_action.execute(meta.index2);
    }
//    action second_bucket_dstport_get_action(){
//        meta.dstport2 = get_second_bucket_dstport_action.execute(meta.index2);
//    }
// Second protocol    ----------------------------   
    Register<bit<8>, bit<HASH_KEY_SIZE>>(ai_character_table_size)  hash_second_bucket_protocol;
    RegisterAction<bit<8>, bit<HASH_KEY_SIZE>, bit<8>>(hash_second_bucket_protocol) put_second_bucket_protocol_action = {
        void apply(inout bit<8> value, out bit<8> return_value) {
            return_value = value;
            value = hdr.ipv4.protocol;
        }
    };
    RegisterAction<bit<8>, bit<HASH_KEY_SIZE>, bit<8>>(hash_second_bucket_protocol) get_second_bucket_protocol_action = {
        void apply(inout bit<8> value, out bit<8> return_value) {
            return_value = value;
            value = hdr.ipv4.protocol;
        }
    };
    
    action second_bucket_protocol_put_action(){
        put_second_bucket_protocol_action.execute(meta.index2);
    }
//    action second_bucket_protocol_get_action(){
//        meta.protocol2 = get_second_bucket_protocol_action.execute(meta.index2);
//    }

// Second pkgnum    ----------------------------  
    Register<bit<8>, bit<HASH_KEY_SIZE>>(ai_character_table_size)  hash_second_bucket_pkgnum;
    RegisterAction<bit<8>, bit<HASH_KEY_SIZE>, bit<8>>(hash_second_bucket_pkgnum) put_second_bucket_pkgnum_action = {
        void apply(inout bit<8> value, out bit<8> return_value) {
            return_value = value;
            value = meta.pkg_num2_writeback;
        }
    };
    RegisterAction<bit<8>, bit<HASH_KEY_SIZE>, bit<8>>(hash_second_bucket_pkgnum) get_second_bucket_pkgnum_action = {
        void apply(inout bit<8> value, out bit<8> return_value) {
            return_value = value;
        }
    };
    RegisterAction<bit<8>, bit<HASH_KEY_SIZE>, bit<8>>(hash_second_bucket_pkgnum) clear_second_bucket_pkgnum_action = {
       void apply(inout bit<8> value, out bit<8> return_value) {
           return_value = value;
           if(meta.second_update_flag == 1){
               value = value - 1;
           }else{
               value = 0;
           }
       }
   };
    
    action second_bucket_pkgnum_put_action(){
        meta.pkg_num2 = put_second_bucket_pkgnum_action.execute(meta.index2);
        
    }
    action second_bucket_pkgnum_get_action(){
        meta.pkg_num2 = get_second_bucket_pkgnum_action.execute(meta.index2);
    }
    action second_bucket_pkgnum_clear_action(){
        meta.pkg_num2 = clear_second_bucket_pkgnum_action.execute(meta.index2);
    }
    
// Second totallen    ----------------------------  
    Register<bit<16>, bit<HASH_KEY_SIZE>>(ai_character_table_size)  hash_second_bucket_totallen;
    RegisterAction<bit<16>, bit<HASH_KEY_SIZE>, bit<16>>(hash_second_bucket_totallen) put_second_bucket_totallen_action = {
        void apply(inout bit<16> value, out bit<16> return_value) {
            return_value = value;
            value = meta.total_len2_writeback;
        }
    };
    RegisterAction<bit<16>, bit<HASH_KEY_SIZE>, bit<16>>(hash_second_bucket_totallen) get_second_bucket_totallen_action = {
        void apply(inout bit<16> value, out bit<16> return_value) {
            return_value = value;
        }
    };
   RegisterAction<bit<16>, bit<HASH_KEY_SIZE>, bit<16>>(hash_second_bucket_totallen) clear_second_bucket_totallen_action = {
       void apply(inout bit<16> value, out bit<16> return_value) {
           return_value = value;
           if(meta.second_update_flag == 1){
               value = value - hdr.ipv4.total_len;
           }else{
               value = 0;
           }
       }
   };

    action second_bucket_totallen_put_action(){
        meta.total_len2 = put_second_bucket_totallen_action.execute(meta.index2);
    }
    action second_bucket_totallen_get_action(){
        meta.total_len2 = get_second_bucket_totallen_action.execute(meta.index2);
    }
    action second_bucket_totallen_clear_action(){
        meta.total_len2 = clear_second_bucket_totallen_action.execute(meta.index2);
    }
    
// Second tstamp    ----------------------------      
    Register<bit<32>, bit<HASH_KEY_SIZE>>(ai_character_table_size)  hash_second_bucket_tstamp;
    RegisterAction<bit<32>, bit<HASH_KEY_SIZE>, bit<32>>(hash_second_bucket_tstamp) put_second_bucket_tstamp_action = {
        void apply(inout bit<32> value, out bit<32> return_value) {
            return_value = value;
            value = ig_intr_md.ingress_mac_tstamp[47:16];
        }
    };
    RegisterAction<bit<32>, bit<HASH_KEY_SIZE>, bit<32>>(hash_second_bucket_tstamp) get_second_bucket_tstamp_action = {
        void apply(inout bit<32> value, out bit<32> return_value) {
            return_value = meta.tstamp - value;
        }
    };

    action second_bucket_tstamp_put_action(){
        put_second_bucket_tstamp_action.execute(meta.index2);
    }
    action second_bucket_tstamp_get_action(){
        meta.tstamp_interval2 = get_second_bucket_tstamp_action.execute(meta.index2);
    }

    table put_first_bucket_srcip_table {
        actions = {
                first_bucket_srcip_put_action;
        }
        default_action = first_bucket_srcip_put_action;
    }
    table put_first_bucket_dstip_table {
        actions = {
                first_bucket_dstip_put_action;
        }
        default_action = first_bucket_dstip_put_action;
    }
    table put_first_bucket_srcport_table {
        actions = {
                first_bucket_srcport_put_action;
        }
        default_action = first_bucket_srcport_put_action;
    }
    table put_first_bucket_dstport_table {
        actions = {
                first_bucket_dstport_put_action;
        }
        default_action = first_bucket_dstport_put_action;
    }
    table put_first_bucket_protocol_table {
        actions = {
                first_bucket_protocol_put_action;
        }
        default_action = first_bucket_protocol_put_action;
    }
    table put_first_bucket_pkgnum_table {
        actions = {
                first_bucket_pkgnum_put_action;
        }
        default_action = first_bucket_pkgnum_put_action;
    }
    table put_first_bucket_totallen_table {
        actions = {
                first_bucket_totallen_put_action;
        }
        default_action = first_bucket_totallen_put_action;
    }
    table put_first_bucket_tstamp_table {
        actions = {
                first_bucket_tstamp_put_action;
        }
        default_action = first_bucket_tstamp_put_action;
    }
    

    table put_second_bucket_srcip_table {
        actions = {
                second_bucket_srcip_put_action;
        }
        default_action = second_bucket_srcip_put_action;
    }
    table put_second_bucket_dstip_table {
        actions = {
                second_bucket_dstip_put_action;
        }
        default_action = second_bucket_dstip_put_action;
    }
    table put_second_bucket_srcport_table {
        actions = {
                second_bucket_srcport_put_action;
        }
        default_action = second_bucket_srcport_put_action;
    }
    table put_second_bucket_dstport_table {
        actions = {
                second_bucket_dstport_put_action;
        }
        default_action = second_bucket_dstport_put_action;
    }
    table put_second_bucket_protocol_table {
        actions = {
                second_bucket_protocol_put_action;
        }
        default_action = second_bucket_protocol_put_action;
    }
    table put_second_bucket_pkgnum_table {
        actions = {
                second_bucket_pkgnum_put_action;
        }
        default_action = second_bucket_pkgnum_put_action;
    }
    table put_second_bucket_totallen_table {
        actions = {
                second_bucket_totallen_put_action;
        }
        default_action = second_bucket_totallen_put_action;
    }
    table put_second_bucket_tstamp_table {
        actions = {
                second_bucket_tstamp_put_action;
        }
        default_action = second_bucket_tstamp_put_action;
    }    


    table clear_first_bucket_pkgnum_table {
        actions = {
                first_bucket_pkgnum_clear_action;
        }
        default_action = first_bucket_pkgnum_clear_action;
    }
    table clear_first_bucket_totallen_table {
        actions = {
                first_bucket_totallen_clear_action;
        }
        default_action = first_bucket_totallen_clear_action;
    }
    table clear_second_bucket_pkgnum_table {
        actions = {
                second_bucket_pkgnum_clear_action;
        }
        default_action = second_bucket_pkgnum_clear_action;
    }
    table clear_second_bucket_totallen_table {
        actions = {
                second_bucket_totallen_clear_action;
        }
        default_action = second_bucket_totallen_clear_action;
    }    

    table get_first_bucket_srcip_table {
        actions = {
                first_bucket_srcip_get_action;
        }
        default_action = first_bucket_srcip_get_action;
    }
    table get_first_bucket_dstip_table {
        actions = {
                first_bucket_dstip_get_action;
        }
        default_action = first_bucket_dstip_get_action;
    }
    table get_first_bucket_srcport_table {
        actions = {
                first_bucket_srcport_get_action;
        }
        default_action = first_bucket_srcport_get_action;
    }
    table get_first_bucket_dstport_table {
        actions = {
                first_bucket_dstport_get_action;
        }
        default_action = first_bucket_dstport_get_action;
    }
    table get_first_bucket_protocol_table {
        actions = {
                first_bucket_protocol_get_action;
        }
        default_action = first_bucket_protocol_get_action;
    }
    table get_first_bucket_pkgnum_table {
        actions = {
                first_bucket_pkgnum_get_action;
        }
        default_action = first_bucket_pkgnum_get_action;
    }
    table get_first_bucket_totallen_table {
        actions = {
                first_bucket_totallen_get_action;
        }
        default_action = first_bucket_totallen_get_action;
    }
    table get_first_bucket_tstamp_interval_table {
        actions={
                first_bucket_tstamp_get_action;
        }
        default_action = first_bucket_tstamp_get_action;
    }
    
//    table get_second_bucket_srcip_table {
//        actions = {
//        		second_bucket_srcip_get_action;
//        }
//        default_action = second_bucket_srcip_get_action;
//    }
//    table get_second_bucket_dstip_table {
//        actions = {
//        		second_bucket_dstip_get_action;
//        }
//        default_action = second_bucket_dstip_get_action;
//    }
//    table get_second_bucket_srcport_table {
//        actions = {
//        		second_bucket_srcport_get_action;
//        }
//        default_action = second_bucket_srcport_get_action;
//    }
//    table get_second_bucket_dstport_table {
//        actions = {
//        		second_bucket_dstport_get_action;
//        }
//        default_action = second_bucket_dstport_get_action;
//    }
//    table get_second_bucket_protocol_table {
//        actions = {
//        		second_bucket_protocol_get_action;
//        }
//        default_action = second_bucket_protocol_get_action;
//    }
    table get_second_bucket_pkgnum_table {
        actions = {
                second_bucket_pkgnum_get_action;
        }
        default_action = second_bucket_pkgnum_get_action;
    }
    table get_second_bucket_totallen_table {
        actions = {
                second_bucket_totallen_get_action;
        }
        default_action = second_bucket_totallen_get_action;
    }
    table get_second_bucket_tstamp_interval_table {
        actions={
                second_bucket_tstamp_get_action;
        }
        default_action = second_bucket_tstamp_get_action;
    }
      
/* 1, black list filter  */
    @pragma stage 0
    table deny_stream {
        key = {
            hdr.ipv4.src_addr: exact;
            hdr.ipv4.dst_addr: exact;
            hdr.ipv4.protocol: exact;
            hdr.ports.src_port : exact;
            hdr.ports.dst_port : exact;
        }
        actions = {
            drop; 
            NoAction;
        }
        
        const default_action = NoAction;
    }
    
/* 2, first hash index calculate */
    Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_first_index_key;
    action do_hash_action() {                                  
        meta.hashout_send = hash_first_index_key.get( {hdr.ipv4.protocol,  hdr.ipv4.src_addr,  hdr.ports.src_port} ); 
    }  
    @pragma stage 0
    table calc_hash_index_key {
        actions = { 
            do_hash_action;
        }                          
        const default_action = do_hash_action();   
    }
    
    Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_first_index_key2;
    action do_hash_action2() {                                  
        meta.hashout_rece = hash_first_index_key2.get( { hdr.ipv4.protocol,  hdr.ipv4.dst_addr,  hdr.ports.dst_port} ); 
     } 

    @pragma stage 0
    table calc_hash_index_key2 {
        actions = { 
            do_hash_action2;
        }                          
        const default_action = do_hash_action2();   
    }
    
/* 3, read exist first hash bucket and determine wether is new */
    Hash<bit<HASH_KEY_SIZE>>(HashAlgorithm_t.CRC32) hash_second_index_key;
    action do_second_hash_action() {   
        meta.index = (bit<HASH_KEY_SIZE>)meta.hashout_rece + (bit<HASH_KEY_SIZE>)meta.hashout_send;
        meta.index2 = hash_second_index_key.get( {meta.hashout_rece, meta.hashout_send} ); 
     }  
    
//    @pragma stage 1
    table calc_second_hash_index_key {
        actions = { 
            do_second_hash_action;
        }                          
        const default_action = do_second_hash_action();   
    }
    
/* 4, read and write in resubmit pipeline */
    action first_bucket_add() {
        meta.first_add_flag = 1;
        meta.pkg_num_writeback = 1;
        meta.total_len_writeback = hdr.ipv4.total_len;
    }
    action first_bucket_add_first_stream_end(){
        meta.first_stream_end_flag = 1;
        meta.first_add_flag = 1;
        meta.pkg_num_writeback = 1;
        meta.total_len_writeback = hdr.ipv4.total_len;
        packet_dir_index = packet_dir_index | 0x4;
    }
    action first_bucket_clear_first_stream_end() {
    	meta.first_stream_end_flag = 1;
        meta.first_add_flag = 1;
        meta.first_clear_flag = 1;
        meta.pkg_num_writeback = 0;
        meta.total_len_writeback = 0;
        packet_dir_index = packet_dir_index | 0x4;
    }
    action first_bucket_update() {
        meta.first_add_flag = 1;
        meta.pkg_num_writeback = meta.pkg_num + 1;
        meta.total_len_writeback = meta.total_len + hdr.ipv4.total_len;
    }
    action first_bucket_add_all_stream_end() {
    	meta.first_stream_end_flag = 1;
    	meta.second_stream_end_flag = 1;
    	meta.first_add_flag = 1;
    	meta.pkg_num_writeback = 1;
    	meta.total_len_writeback = hdr.ipv4.total_len;
    	packet_dir_index = packet_dir_index | 0xC;
    }
    action first_bucket_clear_first_stream_end_second_bucket_add() {
    	meta.first_stream_end_flag = 1;
    	meta.first_add_flag = 1;
    	meta.first_clear_flag = 1;
        meta.pkg_num_writeback = 0;
        meta.total_len_writeback = 0;
        meta.second_add_flag = 1;
    	meta.pkg_num2_writeback = 1;
    	meta.total_len2_writeback = hdr.ipv4.total_len;        
    	packet_dir_index = packet_dir_index | 0x4;
    }
    action second_bucket_add() {
        meta.second_add_flag = 1;
        meta.pkg_num2_writeback = 1;
        meta.total_len2_writeback = hdr.ipv4.total_len;
    }
    action second_bucket_add_second_stream_end() {
        meta.second_stream_end_flag = 1;
        meta.second_add_flag = 1;
        meta.pkg_num2_writeback = 1;
        meta.total_len2_writeback = hdr.ipv4.total_len;
        packet_dir_index = packet_dir_index | 0x8;
    }
    action second_bucket_clear_second_stream_end() {
    	meta.second_stream_end_flag = 1;
        meta.second_add_flag = 1;
        meta.second_clear_flag = 1;
        meta.pkg_num2_writeback = 0;
        meta.total_len2_writeback = 0;
        packet_dir_index = packet_dir_index | 0x8;
    }
    action second_bucket_update() {
        meta.second_add_flag = 1;
        meta.pkg_num2_writeback = meta.pkg_num2 + 1;
        meta.total_len2_writeback = meta.total_len2 + hdr.ipv4.total_len;   	
    }

//    @pragma stage 1
    table resubmit_action {
        key = {
            meta.action_flag : ternary;
        }
        
        actions = {
        	first_bucket_add;
        	first_bucket_add_first_stream_end;
        	first_bucket_clear_first_stream_end;
        	first_bucket_update;
        	first_bucket_add_all_stream_end;
        	first_bucket_clear_first_stream_end_second_bucket_add;
        	second_bucket_add;
        	second_bucket_add_second_stream_end;
        	second_bucket_clear_second_stream_end;
        	second_bucket_update;
            drop;
        }
        
        size = 32;
        const default_action = drop;   
        const entries = {
            16w0x0400 &&& 16w0x7C00: first_bucket_add();
            16w0x03F8 &&& 16w0x7FF8: first_bucket_add_first_stream_end();
            16w0x03F0 &&& 16w0x7FF8: first_bucket_add_first_stream_end();
            16w0x03E8 &&& 16w0x7FF8: first_bucket_clear_first_stream_end();
            16w0x03E0 &&& 16w0x7FF8: first_bucket_update();
            16w0x0012 &&& 16w0x7C16: first_bucket_add_all_stream_end();
            16w0x0014 &&& 16w0x7C14: first_bucket_clear_first_stream_end_second_bucket_add();
            16w0x0004 &&& 16w0x7C04: second_bucket_add();
            16w0x0003 &&& 16w0x7C07: second_bucket_add_second_stream_end();
            16w0x0002 &&& 16w0x7C07: second_bucket_add_second_stream_end();
            16w0x0001 &&& 16w0x7C07: second_bucket_clear_second_stream_end();
            16w0x0000 &&& 16w0x7C07: second_bucket_update();
        }
    }

    action notin_one_second() {
        meta.resubmit_data.action_flag = meta.resubmit_data.action_flag | BIT_TIMEOUT;
//        packet_dir_index = packet_dir_index | 0x1;
    }
    action notin_one_second2() {
        meta.resubmit_data.action_flag = meta.resubmit_data.action_flag | BIT_TIMEOUT2;
//        packet_dir_index = packet_dir_index | 0x2;
    }
    action in_one_second2(){
    }

//    @pragma stage 9
    table detect_timeout_table {
        key = {
            meta.tstamp_interval: ternary;
        }
        actions = {
            notin_one_second; 
            NoAction;
        }
        size = 32;
        const default_action = NoAction;
        const entries = {
        		32w0x80000000 &&& 32w0x80000000: notin_one_second();
        		32w0x40000000 &&& 32w0x40000000: notin_one_second();
        		32w0x20000000 &&& 32w0x20000000: notin_one_second();
        		32w0x10000000 &&& 32w0x10000000: notin_one_second();
        		32w0x08000000 &&& 32w0x08000000: notin_one_second();
        		32w0x04000000 &&& 32w0x04000000: notin_one_second();
        		32w0x02000000 &&& 32w0x02000000: notin_one_second();
        		32w0x01000000 &&& 32w0x01000000: notin_one_second();
        		32w0x00800000 &&& 32w0x00800000: notin_one_second();
        		32w0x00400000 &&& 32w0x00400000: notin_one_second();
        		32w0x00200000 &&& 32w0x00200000: notin_one_second();
        		32w0x00100000 &&& 32w0x00100000: notin_one_second();
        		32w0x00080000 &&& 32w0x00080000: notin_one_second();
        		32w0x00040000 &&& 32w0x00040000: notin_one_second();
        		32w0x00020000 &&& 32w0x00020000: notin_one_second();
        		32w0x00010000 &&& 32w0x00010000: notin_one_second();
        		32w0x00008000 &&& 32w0x00008000: notin_one_second();
        		32w0x00004000 &&& 32w0x00004000: notin_one_second();
        		32w0x00003C00 &&& 32w0x00003C00: notin_one_second();
        		32w0x00003BC0 &&& 32w0x00003FC0: notin_one_second();
        		32w0x00003BB0 &&& 32w0x00003FF0: notin_one_second();
        		32w0x00003BA0 &&& 32w0x00003FF0: notin_one_second();
        		32w0x00003B9B &&& 32w0x00003FFF: notin_one_second();
        		32w0x00003B9C &&& 32w0x00003FFF: notin_one_second();
        		32w0x00003B9D &&& 32w0x00003FFF: notin_one_second();
        		32w0x00003B9E &&& 32w0x00003FFF: notin_one_second();
        		32w0x00003B9F &&& 32w0x00003FFF: notin_one_second();
        }
    }
    
//    @pragma stage 9
    table detect_timeout_table2 {
        key = {
            meta.tstamp_interval2 : ternary;
        }
        actions = {
            notin_one_second2; 
            NoAction;
        }
        size = 32;
        const default_action = NoAction;
        const entries = {
        		32w0x80000000 &&& 32w0x80000000: notin_one_second2();
        		32w0x40000000 &&& 32w0x40000000: notin_one_second2();
        		32w0x20000000 &&& 32w0x20000000: notin_one_second2();
        		32w0x10000000 &&& 32w0x10000000: notin_one_second2();
        		32w0x08000000 &&& 32w0x08000000: notin_one_second2();
        		32w0x04000000 &&& 32w0x04000000: notin_one_second2();
        		32w0x02000000 &&& 32w0x02000000: notin_one_second2();
        		32w0x01000000 &&& 32w0x01000000: notin_one_second2();
        		32w0x00800000 &&& 32w0x00800000: notin_one_second2();
        		32w0x00400000 &&& 32w0x00400000: notin_one_second2();
        		32w0x00200000 &&& 32w0x00200000: notin_one_second2();
        		32w0x00100000 &&& 32w0x00100000: notin_one_second2();
        		32w0x00080000 &&& 32w0x00080000: notin_one_second2();
        		32w0x00040000 &&& 32w0x00040000: notin_one_second2();
        		32w0x00020000 &&& 32w0x00020000: notin_one_second2();
        		32w0x00010000 &&& 32w0x00010000: notin_one_second2();
        		32w0x00008000 &&& 32w0x00008000: notin_one_second2();
        		32w0x00004000 &&& 32w0x00004000: notin_one_second2();
        		32w0x00003C00 &&& 32w0x00003C00: notin_one_second2();
        		32w0x00003BC0 &&& 32w0x00003FC0: notin_one_second2();
        		32w0x00003BB0 &&& 32w0x00003FF0: notin_one_second2();
        		32w0x00003BA0 &&& 32w0x00003FF0: notin_one_second2();
        		32w0x00003B9B &&& 32w0x00003FFF: notin_one_second2();
        		32w0x00003B9C &&& 32w0x00003FFF: notin_one_second2();
        		32w0x00003B9D &&& 32w0x00003FFF: notin_one_second2();
        		32w0x00003B9E &&& 32w0x00003FFF: notin_one_second2();
        		32w0x00003B9F &&& 32w0x00003FFF: notin_one_second2();
        }
    }
    
    action flow_match_action(){
        meta.resubmit_data.action_flag = meta.resubmit_data.action_flag | 0x20;
    }
    @pragma stage 5
    table detect_flowmatch_table {
        key = {
            meta.subsip      : ternary;
            meta.subsport    : ternary;
            meta.subdip      : ternary;
            meta.subdport    : ternary;
            meta.subprotocol : ternary;
            meta.subsip2     : ternary;
            meta.subsport2   : ternary;
            meta.subdip2     : ternary;
            meta.subdport2   : ternary;
        }
        actions = {
            flow_match_action; 
            NoAction;
        }
        size = 256;
        const default_action = NoAction;
        const entries = {
                (0, 0, 0, 0, 0, _, _, _, _) : flow_match_action();
                (_, _, _, _, 0, 0, 0, 0, 0) : flow_match_action();
        }
    }
   

    
    action stream_character_to_cpu() {
        hdr.common.type = PKT_TYPE_MIRROR_ABNORMAL;
        hdr.cpu_ethernet.setInvalid();
        hdr.cpu_ethernet.dst_addr   = 0xFFFFFFFFFFFF;
        hdr.cpu_ethernet.src_addr   = 0xABABABABABAB;
        hdr.cpu_ethernet.ether_type = 0xDEAF;
        
        hdr.to_cpu.setInvalid();
        hdr.to_cpu.pkg_num = meta.pkg_num;
        hdr.to_cpu.total_len = meta.total_len;
        ai_dect_index = ai_dect_index | 0x1;
    }
    action stream_character_to_cpu2() {
        hdr.common.type = PKT_TYPE_MIRROR_ABNORMAL;
        hdr.cpu_ethernet.setInvalid();
        hdr.cpu_ethernet.dst_addr   = 0xFFFFFFFFFFFF;
        hdr.cpu_ethernet.src_addr   = 0xABABABABABAB;
        hdr.cpu_ethernet.ether_type = 0xDEAF;
        
        hdr.to_cpu.setInvalid();
        hdr.to_cpu.pkg_num2 = meta.pkg_num2;
        hdr.to_cpu.total_len2 = meta.total_len2;
        ai_dect_index = ai_dect_index | 0x2;
    }
    action stream_character_normal() {
    	hdr.common.type = PKT_TYPE_MIRROR_NORMAL;
    	hdr.cpu_ethernet.setInvalid();
    	hdr.to_cpu.setInvalid();
    	ai_dect_index = ai_dect_index | 0x4;
    }
    
    table detect_abnormal_stream {
        key = {
            meta.first_stream_end_flag : exact;
            hdr.ipv4.protocol : exact;
            meta.pkg_num : exact;
            meta.total_len : range;
        }
        actions = {
        	stream_character_to_cpu; 
        	stream_character_normal;
        }
        size = 128;
        const default_action = stream_character_to_cpu;
        const entries = {
        		(0,  6,  0,    0..65535) : stream_character_normal();
        		(0,  6,  1,    1..65535) : stream_character_normal();
        		(0,  6,  2,    1..65535) : stream_character_normal();
        		(0,  6,  3,    1..65535) : stream_character_normal();
        		(0,  6,  4,    1..65535) : stream_character_normal();
        		(0,  6,  5,    1..65535) : stream_character_normal();
        		(0,  6,  6,    1..65535) : stream_character_normal();
        		(0,  6,  7,    1..65535) : stream_character_normal();
        		(0,  6,  8,    1..65535) : stream_character_normal();
        		(0,  6,  9,    1..65535) : stream_character_normal();
        		(0,  6, 10,    1..65535) : stream_character_normal();
        		(0,  6, 11,    1..65535) : stream_character_normal();
        		(0,  6, 12,    1..65535) : stream_character_normal();
        		(0,  6, 13,    1..65535) : stream_character_normal();
        		(0,  6, 14,    1..65535) : stream_character_normal();
        		(0,  6, 15,    1..65535) : stream_character_normal();
        		(1,  6,  1,    1..40   ) : stream_character_normal();
        		(1,  6,  2,  105..148  ) : stream_character_normal();
        		(1,  6,  2,  166..247  ) : stream_character_normal();
        		(1,  6,  3,  214..231  ) : stream_character_normal();
        		(1,  6,  3,  544..644  ) : stream_character_normal();
        		(1,  6,  5,  428..474  ) : stream_character_normal();
        		(1,  6, 15, 3377..3477 ) : stream_character_normal();
        		(1,  6, 15, 3479..3480 ) : stream_character_normal();
        		(1,  6, 15, 3484..3490 ) : stream_character_normal();
        		(1,  6, 15, 3510..3510 ) : stream_character_normal();
        		(1,  6, 15, 3528..3538 ) : stream_character_normal();
        		(1,  6, 15, 3547..4090 ) : stream_character_normal();
        		(1,  6, 15, 4104..4124 ) : stream_character_normal();
        		(1,  6, 15, 4140..4141 ) : stream_character_normal();
        		(1,  6, 15, 4143..4158 ) : stream_character_normal();
        		(1,  6, 15, 7483..7507 ) : stream_character_normal();
        		(0, 17,  0,    0..65535) : stream_character_normal();
        		(0, 17,  1,    1..65535) : stream_character_normal();
        		(0, 17,  2,    1..65535) : stream_character_normal();
        		(0, 17,  3,    1..65535) : stream_character_normal();
        		(0, 17,  4,    1..65535) : stream_character_normal();
        		(0, 17,  5,    1..65535) : stream_character_normal();
        		(0, 17,  6,    1..65535) : stream_character_normal();
        		(0, 17,  7,    1..65535) : stream_character_normal();
        		(0, 17,  8,    1..65535) : stream_character_normal();
        		(0, 17,  9,    1..65535) : stream_character_normal();
        		(0, 17, 10,    1..65535) : stream_character_normal();
        		(0, 17, 11,    1..65535) : stream_character_normal();
        		(0, 17, 12,    1..65535) : stream_character_normal();
        		(0, 17, 13,    1..65535) : stream_character_normal();
        		(0, 17, 14,    1..65535) : stream_character_normal();
        		(0, 17, 15,    1..65535) : stream_character_normal();
        		(1, 17,  1,   37..41   ) : stream_character_normal();
        		(1, 17,  1,   63..70   ) : stream_character_normal();
        		(1, 17,  1,  291..328  ) : stream_character_normal();
        		(1, 17,  2,  144..156  ) : stream_character_normal();
        		(1, 17,  2,  192..193  ) : stream_character_normal();
        		(1, 17,  6,  308..324  ) : stream_character_normal();
        		(1, 17, 14, 1509..1536 ) : stream_character_normal();
        		(1, 17, 14, 1539..1540 ) : stream_character_normal();
        		(1, 17, 15,  719..722  ) : stream_character_normal();
        		(1, 17, 15,  834..848  ) : stream_character_normal();
        		(1, 17, 15, 1477..1834 ) : stream_character_normal();
        		(1, 17, 15, 1847..1847 ) : stream_character_normal();
        		(1, 17, 15, 1849..1920 ) : stream_character_normal();
        		(1, 17, 15, 1949..1950 ) : stream_character_normal();
        		(1, 17, 15, 1953..1956 ) : stream_character_normal();
        		(1, 17, 15, 1968..1969 ) : stream_character_normal();
        		(1, 17, 15, 2029..2351 ) : stream_character_normal();
        		(1, 17, 15, 2429..2445 ) : stream_character_normal();
        		(1, 17, 15, 2485..2530 ) : stream_character_normal();
        		(1, 17, 15, 2534..2535 ) : stream_character_normal();
        		(1, 17, 15, 2660..2709 ) : stream_character_normal();
        		(1, 17, 15, 2801..2850 ) : stream_character_normal();
        		(1, 17, 15, 2852..2852 ) : stream_character_normal();
        		(1, 17, 15, 2857..2890 ) : stream_character_normal();
        		(1, 17, 15, 2945..2945 ) : stream_character_normal();
        		(1, 17, 15, 2947..2948 ) : stream_character_normal();
        		(1, 17, 15, 2984..3017 ) : stream_character_normal();
        		// Compiler tricks to avoid compile failures
        		(1, 17, 15, 3018..3100 ) : stream_character_to_cpu();
        }
    }
    
    table detect_abnormal_stream2 {
        key = {
            meta.second_stream_end_flag : exact;
            hdr.ipv4.protocol : exact;
            meta.pkg_num2 : exact;
            meta.total_len2 : range;
        }
        actions = {
        	stream_character_to_cpu2; 
        	stream_character_normal;
        }
        size = 128;
        const default_action = stream_character_to_cpu2;
        const entries = {
        		(0,  6,  0,    0..65535) : stream_character_normal();
        		(0,  6,  1,    1..65535) : stream_character_normal();
        		(0,  6,  2,    1..65535) : stream_character_normal();
        		(0,  6,  3,    1..65535) : stream_character_normal();
        		(0,  6,  4,    1..65535) : stream_character_normal();
        		(0,  6,  5,    1..65535) : stream_character_normal();
        		(0,  6,  6,    1..65535) : stream_character_normal();
        		(0,  6,  7,    1..65535) : stream_character_normal();
        		(0,  6,  8,    1..65535) : stream_character_normal();
        		(0,  6,  9,    1..65535) : stream_character_normal();
        		(0,  6, 10,    1..65535) : stream_character_normal();
        		(0,  6, 11,    1..65535) : stream_character_normal();
        		(0,  6, 12,    1..65535) : stream_character_normal();
        		(0,  6, 13,    1..65535) : stream_character_normal();
        		(0,  6, 14,    1..65535) : stream_character_normal();
        		(0,  6, 15,    1..65535) : stream_character_normal();
        		(1,  6,  1,    1..40   ) : stream_character_normal();
        		(1,  6,  2,  105..148  ) : stream_character_normal();
        		(1,  6,  2,  166..247  ) : stream_character_normal();
        		(1,  6,  3,  214..231  ) : stream_character_normal();
        		(1,  6,  3,  544..644  ) : stream_character_normal();
        		(1,  6,  5,  428..474  ) : stream_character_normal();
        		(1,  6, 15, 3377..3477 ) : stream_character_normal();
        		(1,  6, 15, 3479..3480 ) : stream_character_normal();
        		(1,  6, 15, 3484..3490 ) : stream_character_normal();
        		(1,  6, 15, 3510..3510 ) : stream_character_normal();
        		(1,  6, 15, 3528..3538 ) : stream_character_normal();
        		(1,  6, 15, 3547..4090 ) : stream_character_normal();
        		(1,  6, 15, 4104..4124 ) : stream_character_normal();
        		(1,  6, 15, 4140..4141 ) : stream_character_normal();
        		(1,  6, 15, 4143..4158 ) : stream_character_normal();
        		(1,  6, 15, 7483..7507 ) : stream_character_normal();
        		(0, 17,  0,    0..65535) : stream_character_normal();
        		(0, 17,  1,    1..65535) : stream_character_normal();
        		(0, 17,  2,    1..65535) : stream_character_normal();
        		(0, 17,  3,    1..65535) : stream_character_normal();
        		(0, 17,  4,    1..65535) : stream_character_normal();
        		(0, 17,  5,    1..65535) : stream_character_normal();
        		(0, 17,  6,    1..65535) : stream_character_normal();
        		(0, 17,  7,    1..65535) : stream_character_normal();
        		(0, 17,  8,    1..65535) : stream_character_normal();
        		(0, 17,  9,    1..65535) : stream_character_normal();
        		(0, 17, 10,    1..65535) : stream_character_normal();
        		(0, 17, 11,    1..65535) : stream_character_normal();
        		(0, 17, 12,    1..65535) : stream_character_normal();
        		(0, 17, 13,    1..65535) : stream_character_normal();
        		(0, 17, 14,    1..65535) : stream_character_normal();
        		(0, 17, 15,    1..65535) : stream_character_normal();
        		(1, 17,  1,   37..41   ) : stream_character_normal();
        		(1, 17,  1,   63..70   ) : stream_character_normal();
        		(1, 17,  1,  291..328  ) : stream_character_normal();
        		(1, 17,  2,  144..156  ) : stream_character_normal();
        		(1, 17,  2,  192..193  ) : stream_character_normal();
        		(1, 17,  6,  308..324  ) : stream_character_normal();
        		(1, 17, 14, 1509..1536 ) : stream_character_normal();
        		(1, 17, 14, 1539..1540 ) : stream_character_normal();
        		(1, 17, 15,  719..722  ) : stream_character_normal();
        		(1, 17, 15,  834..848  ) : stream_character_normal();
        		(1, 17, 15, 1477..1834 ) : stream_character_normal();
        		(1, 17, 15, 1847..1847 ) : stream_character_normal();
        		(1, 17, 15, 1849..1920 ) : stream_character_normal();
        		(1, 17, 15, 1949..1950 ) : stream_character_normal();
        		(1, 17, 15, 1953..1956 ) : stream_character_normal();
        		(1, 17, 15, 1968..1969 ) : stream_character_normal();
        		(1, 17, 15, 2029..2351 ) : stream_character_normal();
        		(1, 17, 15, 2429..2445 ) : stream_character_normal();
        		(1, 17, 15, 2485..2530 ) : stream_character_normal();
        		(1, 17, 15, 2534..2535 ) : stream_character_normal();
        		(1, 17, 15, 2660..2709 ) : stream_character_normal();
        		(1, 17, 15, 2801..2850 ) : stream_character_normal();
        		(1, 17, 15, 2852..2852 ) : stream_character_normal();
        		(1, 17, 15, 2857..2890 ) : stream_character_normal();
        		(1, 17, 15, 2945..2945 ) : stream_character_normal();
        		(1, 17, 15, 2947..2948 ) : stream_character_normal();
        		(1, 17, 15, 2984..3017 ) : stream_character_normal();
        		// Compiler tricks to avoid compile failures
        		(1, 17, 15, 3018..3100 ) : stream_character_to_cpu2();
        }
    }
    
/* 5, Main Pipeline  */
    apply {
        // stage 0
    	set_current_tstamp.apply();
        deny_stream.apply();
        calc_hash_index_key.apply();
        calc_hash_index_key2.apply();
        // stage 1
        calc_second_hash_index_key.apply();
        	
        if(meta.action_flag == 0) {
            // Get all data in first bucket and save to meta
            get_first_bucket_srcip_table.apply();
            get_first_bucket_dstip_table.apply();
            get_first_bucket_srcport_table.apply();
            get_first_bucket_dstport_table.apply();
            get_first_bucket_protocol_table.apply();
            get_first_bucket_pkgnum_table.apply();
            get_first_bucket_totallen_table.apply();
            get_first_bucket_tstamp_interval_table.apply();
            
            // Get key(five tuple) in second bucket and save to meta data
            //get_second_bucket_srcip_table.apply();
            //get_second_bucket_dstip_table.apply();
            //get_second_bucket_srcport_table.apply();
            //get_second_bucket_dstport_table.apply();
            //get_second_bucket_protocol_table.apply();
            // Get data(pkgnum, total_len, timestamp) in second bucket and save to meta
            get_second_bucket_pkgnum_table.apply();
            get_second_bucket_totallen_table.apply();
            get_second_bucket_tstamp_interval_table.apply();
            
            detect_flowmatch_table.apply();
          
//            if (meta.srcip == hdr.ipv4.src_addr ) {  // || meta.srcip == hdr.ipv4.dst_addr
//                meta.resubmit_data.action_flag = meta.resubmit_data.action_flag | BIT_SRC_ADDR;
//            }
//
//            if (meta.dstip == hdr.ipv4.dst_addr ) { // || meta.dstip == hdr.ipv4.src_addr
//                meta.resubmit_data.action_flag = meta.resubmit_data.action_flag | BIT_DST_ADDR;
//            }
//
//            if (meta.protocol == hdr.ipv4.protocol) {
//                meta.resubmit_data.action_flag = meta.resubmit_data.action_flag | BIT_PROTOCOL;
//            }
//
//            if (meta.srcport == hdr.ports.src_port ) {// && meta.srcport == hdr.ports.dst_port
//                meta.resubmit_data.action_flag = meta.resubmit_data.action_flag | BIT_SRC_PORT;
//            }
//
//            if ( meta.dstport == hdr.ports.dst_port){  // && meta.dstport == hdr.ports.src_port
//                meta.resubmit_data.action_flag = meta.resubmit_data.action_flag | BIT_DST_PORT;
//            }

            if (meta.pkg_num == 0) {
                meta.resubmit_data.action_flag = meta.resubmit_data.action_flag | BIT_EMPTY;
                packet_dir_index = packet_dir_index | 0x1;
            } else if (meta.pkg_num >= 14 ){
                meta.resubmit_data.action_flag = meta.resubmit_data.action_flag | BIT_PKG_NUM;
                packet_dir_index = packet_dir_index | 0x2;
            }

            if(meta.pkg_num2 == 0) {
                meta.resubmit_data.action_flag = meta.resubmit_data.action_flag | BIT_EMPTY2;
                packet_dir_index = packet_dir_index | 0x4;
            } else if(meta.pkg_num2 > 14) {
                meta.resubmit_data.action_flag = meta.resubmit_data.action_flag | BIT_PKG_NUM2;
                packet_dir_index = packet_dir_index | 0x8;
            }
            
            detect_timeout_table.apply();
            detect_timeout_table2.apply();
            set_submit();
        } else {
        	ig_dprsr_md.resubmit_type = 0;
        	ig_dprsr_md.mirror_type = 1; // Ingress Mirror
            ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
            resubmit_action.apply();
            
            if(meta.first_clear_flag == 0) {
                put_first_bucket_srcip_table.apply();
                put_first_bucket_dstip_table.apply();
                put_first_bucket_srcport_table.apply();
                put_first_bucket_dstport_table.apply();
                put_first_bucket_protocol_table.apply();
            }

            if(meta.first_add_flag == 1){       
                put_first_bucket_pkgnum_table.apply();
                put_first_bucket_totallen_table.apply();
                put_first_bucket_tstamp_table.apply();
                ai_dect_index = ai_dect_index | 0x8;
            }
            
            if(meta.second_clear_flag == 0) {
                put_second_bucket_srcip_table.apply();
                put_second_bucket_dstip_table.apply();
                put_second_bucket_srcport_table.apply();
                put_second_bucket_dstport_table.apply();
                put_second_bucket_protocol_table.apply();    
            }
            
            if(meta.second_add_flag == 1){     
                put_second_bucket_pkgnum_table.apply();
                put_second_bucket_totallen_table.apply();
                put_second_bucket_tstamp_table.apply();
                ai_dect_index = ai_dect_index | 0x10;
            }
            packet_dir_index = packet_dir_index | 0x10;
            hdr.common.setValid();
            hdr.common.type = PKT_TYPE_NORMAL;
            detect_abnormal_stream.apply();
            detect_abnormal_stream2.apply();
            ai_dect_stats.count(ai_dect_index);
        }
        packet_dir_stats.count(packet_dir_index);
    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Resubmit() resubmit;
    Mirror() mirror;
    apply {
        if (ig_dprsr_md.resubmit_type == 2) {
           resubmit.emit(meta.resubmit_data);
        }
        if (ig_dprsr_md.mirror_type == 1) {
        	mirror.emit<ing_port_mirror_h>(meta.mirror_session, {
        			hdr.common.type, hdr.cpu_ethernet.dst_addr, hdr.cpu_ethernet.src_addr, hdr.cpu_ethernet.ether_type, meta.pkg_num, meta.total_len, meta.pkg_num2, meta.total_len2
        	});
        }
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
	common_header_h common;
    ethernet_h      cpu_ethernet;
    to_cpu_h        to_cpu;
}

struct my_egress_headers_t {
    
}


    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);

        transition parse_bridge;
    }
    
    state parse_bridge {
        pkt.extract(meta.common);

        transition select(meta.common.type) {
            PKT_TYPE_MIRROR_ABNORMAL: parse_cpu_header;
            PKT_TYPE_MIRROR_NORMAL: parse_abnormal_header;
            PKT_TYPE_NORMAL:    parse_normal;
            default: accept;
        }
    }
    
    state parse_cpu_header {
        transition accept;
    }
    state parse_abnormal_header {
        pkt.extract(meta.cpu_ethernet);
        pkt.extract(meta.to_cpu);
        
        transition accept;
    }
    
    state parse_normal{
    	transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control EgressAI(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
//    action send_to_cpu(){
//        hdr.cpu_ethernet.setValid();
//        hdr.cpu_ethernet.dst_addr    = 0xFFFFFFFFFFFF;
//        hdr.cpu_ethernet.src_addr    = 0xABABABABABAB;
//        hdr.cpu_ethernet.ether_type    = 0xDEAD;
//        
//        hdr.to_cpu.setValid();
//        hdr.to_cpu.ingress_port = meta.ingress_port;
//        hdr.to_cpu.pkg_num = meta.pkg_num;
//        hdr.to_cpu.total_len = meta.total_len;
//        hdr.to_cpu.ingress_mac_tstamp = meta.ingress_mac_tstamp;
//    }
    apply {
        // if to cpu, Add a layer of ehternet encapsulation
//        hdr.common.setInvalid();

//        if(eg_intr_md.egress_rid != 0 || eg_intr_md.egress_rid_first != 1){  
//            hdr.to_cpu.setInvalid();
//            hdr.cpu_ethernet.setInvalid();
//        }
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md,
    in      egress_intrinsic_metadata_t eg_intr_md) 
{
    apply {
//        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    IngressAI(),
    IngressDeparser(),
    EgressParser(),
    EgressAI(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
