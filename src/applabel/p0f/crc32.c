/*

   p0f - cyclic redundancy check
   -----------------------------

   CRC32 code. Polynomial 0x04c11db7LU.

   Copyright (C) 2006 by Mariusz Kozlowski <m.kozlowski@tuxland.pl>



 */

#define _YAF_SOURCE_
#include <yaf/autoinc.h>


static const uint32_t crc32table[] = {
  0x00000000LU, 0x77073096LU, 0xee0e612cLU, 0x990951baLU,
  0x076dc419LU, 0x706af48fLU, 0xe963a535LU, 0x9e6495a3LU,
  0x0edb8832LU, 0x79dcb8a4LU, 0xe0d5e91eLU, 0x97d2d988LU,
  0x09b64c2bLU, 0x7eb17cbdLU, 0xe7b82d07LU, 0x90bf1d91LU,
  0x1db71064LU, 0x6ab020f2LU, 0xf3b97148LU, 0x84be41deLU,
  0x1adad47dLU, 0x6ddde4ebLU, 0xf4d4b551LU, 0x83d385c7LU,
  0x136c9856LU, 0x646ba8c0LU, 0xfd62f97aLU, 0x8a65c9ecLU,
  0x14015c4fLU, 0x63066cd9LU, 0xfa0f3d63LU, 0x8d080df5LU,
  0x3b6e20c8LU, 0x4c69105eLU, 0xd56041e4LU, 0xa2677172LU,
  0x3c03e4d1LU, 0x4b04d447LU, 0xd20d85fdLU, 0xa50ab56bLU,
  0x35b5a8faLU, 0x42b2986cLU, 0xdbbbc9d6LU, 0xacbcf940LU,
  0x32d86ce3LU, 0x45df5c75LU, 0xdcd60dcfLU, 0xabd13d59LU,
  0x26d930acLU, 0x51de003aLU, 0xc8d75180LU, 0xbfd06116LU,
  0x21b4f4b5LU, 0x56b3c423LU, 0xcfba9599LU, 0xb8bda50fLU,
  0x2802b89eLU, 0x5f058808LU, 0xc60cd9b2LU, 0xb10be924LU,
  0x2f6f7c87LU, 0x58684c11LU, 0xc1611dabLU, 0xb6662d3dLU,
  0x76dc4190LU, 0x01db7106LU, 0x98d220bcLU, 0xefd5102aLU,
  0x71b18589LU, 0x06b6b51fLU, 0x9fbfe4a5LU, 0xe8b8d433LU,
  0x7807c9a2LU, 0x0f00f934LU, 0x9609a88eLU, 0xe10e9818LU,
  0x7f6a0dbbLU, 0x086d3d2dLU, 0x91646c97LU, 0xe6635c01LU,
  0x6b6b51f4LU, 0x1c6c6162LU, 0x856530d8LU, 0xf262004eLU,
  0x6c0695edLU, 0x1b01a57bLU, 0x8208f4c1LU, 0xf50fc457LU,
  0x65b0d9c6LU, 0x12b7e950LU, 0x8bbeb8eaLU, 0xfcb9887cLU,
  0x62dd1ddfLU, 0x15da2d49LU, 0x8cd37cf3LU, 0xfbd44c65LU,
  0x4db26158LU, 0x3ab551ceLU, 0xa3bc0074LU, 0xd4bb30e2LU,
  0x4adfa541LU, 0x3dd895d7LU, 0xa4d1c46dLU, 0xd3d6f4fbLU,
  0x4369e96aLU, 0x346ed9fcLU, 0xad678846LU, 0xda60b8d0LU,
  0x44042d73LU, 0x33031de5LU, 0xaa0a4c5fLU, 0xdd0d7cc9LU,
  0x5005713cLU, 0x270241aaLU, 0xbe0b1010LU, 0xc90c2086LU,
  0x5768b525LU, 0x206f85b3LU, 0xb966d409LU, 0xce61e49fLU,
  0x5edef90eLU, 0x29d9c998LU, 0xb0d09822LU, 0xc7d7a8b4LU,
  0x59b33d17LU, 0x2eb40d81LU, 0xb7bd5c3bLU, 0xc0ba6cadLU,
  0xedb88320LU, 0x9abfb3b6LU, 0x03b6e20cLU, 0x74b1d29aLU,
  0xead54739LU, 0x9dd277afLU, 0x04db2615LU, 0x73dc1683LU,
  0xe3630b12LU, 0x94643b84LU, 0x0d6d6a3eLU, 0x7a6a5aa8LU,
  0xe40ecf0bLU, 0x9309ff9dLU, 0x0a00ae27LU, 0x7d079eb1LU,
  0xf00f9344LU, 0x8708a3d2LU, 0x1e01f268LU, 0x6906c2feLU,
  0xf762575dLU, 0x806567cbLU, 0x196c3671LU, 0x6e6b06e7LU,
  0xfed41b76LU, 0x89d32be0LU, 0x10da7a5aLU, 0x67dd4accLU,
  0xf9b9df6fLU, 0x8ebeeff9LU, 0x17b7be43LU, 0x60b08ed5LU,
  0xd6d6a3e8LU, 0xa1d1937eLU, 0x38d8c2c4LU, 0x4fdff252LU,
  0xd1bb67f1LU, 0xa6bc5767LU, 0x3fb506ddLU, 0x48b2364bLU,
  0xd80d2bdaLU, 0xaf0a1b4cLU, 0x36034af6LU, 0x41047a60LU,
  0xdf60efc3LU, 0xa867df55LU, 0x316e8eefLU, 0x4669be79LU,
  0xcb61b38cLU, 0xbc66831aLU, 0x256fd2a0LU, 0x5268e236LU,
  0xcc0c7795LU, 0xbb0b4703LU, 0x220216b9LU, 0x5505262fLU,
  0xc5ba3bbeLU, 0xb2bd0b28LU, 0x2bb45a92LU, 0x5cb36a04LU,
  0xc2d7ffa7LU, 0xb5d0cf31LU, 0x2cd99e8bLU, 0x5bdeae1dLU,
  0x9b64c2b0LU, 0xec63f226LU, 0x756aa39cLU, 0x026d930aLU,
  0x9c0906a9LU, 0xeb0e363fLU, 0x72076785LU, 0x05005713LU,
  0x95bf4a82LU, 0xe2b87a14LU, 0x7bb12baeLU, 0x0cb61b38LU,
  0x92d28e9bLU, 0xe5d5be0dLU, 0x7cdcefb7LU, 0x0bdbdf21LU,
  0x86d3d2d4LU, 0xf1d4e242LU, 0x68ddb3f8LU, 0x1fda836eLU,
  0x81be16cdLU, 0xf6b9265bLU, 0x6fb077e1LU, 0x18b74777LU,
  0x88085ae6LU, 0xff0f6a70LU, 0x66063bcaLU, 0x11010b5cLU,
  0x8f659effLU, 0xf862ae69LU, 0x616bffd3LU, 0x166ccf45LU,
  0xa00ae278LU, 0xd70dd2eeLU, 0x4e048354LU, 0x3903b3c2LU,
  0xa7672661LU, 0xd06016f7LU, 0x4969474dLU, 0x3e6e77dbLU,
  0xaed16a4aLU, 0xd9d65adcLU, 0x40df0b66LU, 0x37d83bf0LU,
  0xa9bcae53LU, 0xdebb9ec5LU, 0x47b2cf7fLU, 0x30b5ffe9LU,
  0xbdbdf21cLU, 0xcabac28aLU, 0x53b39330LU, 0x24b4a3a6LU,
  0xbad03605LU, 0xcdd70693LU, 0x54de5729LU, 0x23d967bfLU,
  0xb3667a2eLU, 0xc4614ab8LU, 0x5d681b02LU, 0x2a6f2b94LU,
  0xb40bbe37LU, 0xc30c8ea1LU, 0x5a05df1bLU, 0x2d02ef8dLU
};

uint32_t crc32(uint8_t *data, uint32_t len)
{
  uint32_t crc=0xffffffff;

  while (len--)
	  crc=(crc>>8)^crc32table[(crc&0xff)^*data++];
  return crc^0xffffffff;
}

