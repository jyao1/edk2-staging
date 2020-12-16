# This TD-SHIM POC

It only has reset vector, IPL and jump to a payload.

## Payload

It is a sample payload, supporting below interface.

1) Memory Map - E820 table.

2) MP table - include MP wakeup vector.

3) TD Measurement - a TD event log table.

## Build Step:

1) build -p TdShimPkg\TdShimPkg.dsc -a X64 -t VS2015x86 -D DEBUG_ON_SERIAL_PORT -y report.log

2) TdShimPkg\Scripts\tdvf_metadata.py -t Build\TdShim\DEBUG_VS2015x86\FV\TDSHIM.fd -o Build\TdShim\DEBUG_VS2015x86\FV\TDSHIM.final.fd

The TDSHIM.final.fd is used to launch.

## Known limitation
This package is only the sample code to show the concept.
It does not have a full validation such as robustness functional test and fuzzing test. It does not meet the production quality yet.
Any codes including the API definition, the libary and the drivers are subject to change.
