#pragma once
#include "stdafx.h"

//  URI Macros
#define SYSLINK_URI							"http://192.99.58.184/DizzyV6"
#define SYSLINK_BUILD_URL( path )			SYSLINK_URI path
#define QUICKLAUNCH_ID_Request			SYSLINK_BUILD_URL("quicklaunch.php?cpu=%s", m_szCPUKey)

//void UploadFile();

