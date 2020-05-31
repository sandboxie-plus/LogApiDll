# libApiLog
API logging Library for Buster Sandbox Analyzer

## Usage
You need sandboxie to use the LogApiDll's in the sandboxie.ini you need to enable the dll injection and open the required communication pipe

```
InjectDll=...\logapi32.dll
InjectDll64=...\logapi64.dll
OpenPipePath=\Device\NamedPipe\LogAPI
```

Once this is set up you must open a pipe server at \\\\.\\pipe\\LogAPI and you will get the log messages  as a '\0' separated stream of data.
