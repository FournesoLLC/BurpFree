$ErrorActionPreference = 'Stop'
$cli = "c:\Users\pc\Desktop\BurpFree\target\debug\burpfree.exe"
$proj = Join-Path $env:TEMP "burpfree-smoke-api"
$spec = Join-Path $env:TEMP "burpfree-smoke-api.yaml"
if (Test-Path $proj) { Remove-Item -Recurse -Force $proj }
if (Test-Path $spec) { Remove-Item -Force $spec }

& $cli project new $proj | Out-Null

$yaml = @"
openapi: 3.0.0
info:
  title: pets
  version: 1.0.0
servers:
  - url: https://api.example.com/v1
paths:
  /pets:
    get:
      operationId: listPets
      parameters:
        - {name: limit, in: query, schema: {type: integer}}
    post:
      operationId: createPet
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                name: {type: string}
                tag: {type: string}
  /pets/{id}:
    get:
      operationId: getPet
      parameters:
        - {name: id, in: path, schema: {type: integer}}
    delete:
      operationId: deletePet
      parameters:
        - {name: id, in: path, schema: {type: integer}}
"@
# Write bytes directly to avoid a UTF-8 BOM.
[IO.File]::WriteAllText($spec, $yaml, [Text.UTF8Encoding]::new($false))

Write-Output "=== import openapi ==="
& $cli import --project $proj $spec

Write-Output ""
Write-Output "=== history after import ==="
& $cli history --project $proj list --limit 10
Write-Output ""
Write-Output "count: $(& $cli history --project $proj count)"

$pm = Join-Path $env:TEMP "burpfree-smoke-pm.json"
$json = @"
{
  "info": {"name":"demo","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
  "item":[
    {"name":"users-list","request":"https://api.example.com/users"},
    {"name":"users-create","request":{"method":"POST","header":[{"key":"Content-Type","value":"application/json"}],"url":"https://api.example.com/users","body":{"mode":"raw","raw":"{\"name\":\"alice\"}"}}}
  ]
}
"@
[IO.File]::WriteAllText($pm, $json, [Text.UTF8Encoding]::new($false))

Write-Output ""
Write-Output "=== import postman ==="
& $cli import --project $proj $pm --format postman

Write-Output "count after both imports: $(& $cli history --project $proj count)"

Remove-Item -Force $spec, $pm -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $proj
Write-Output "DONE"
