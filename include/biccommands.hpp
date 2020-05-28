

#define NETFUN_FB_OEM_BIC 0x38

enum fb_oem_bic
{
	CMD_OEM_BIC_INFO = 0x1
};


typedef struct
{
  uint8_t data[4];

  struct 
  {
    uint8_t netfn;
    uint8_t cmd;
    std::vector<uint8_t> data;
  }ipmi_req; 

}ipmi_bic_req_t;
