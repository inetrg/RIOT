## Usage

This app can be used to measure processing time and energy consumption of the ATECC608A sha256 function.

#### Options

- To test energy consumption build with TEST_ENERGY=1
- To read and store the context between function calls, build with ATCA_SAVE_CTX=1
- To manually wake and put the device to sleep, build with ATCA_MANUAL_ONOFF=1
- To disable I2C Reconfigure build with NO_I2C_RECONF=1