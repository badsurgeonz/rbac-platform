param(
    [string]$GatewayUrl = "http://localhost:8080",
    [string]$Username = "admin",
    [string]$Password = "password"
)

$ErrorActionPreference = "Stop"

function Assert-Status([int]$Actual, [int]$Expected, [string]$Name) {
    if ($Actual -ne $Expected) { throw "$Name expected HTTP $Expected but received HTTP $Actual" }
    Write-Host "PASS $Name"
}

function Invoke-Raw($Method, $Uri, $Headers = @{}, $Body = $null) {
    try {
        $params = @{ Method = $Method; Uri = $Uri; Headers = $Headers; SkipHttpErrorCheck = $true }
        if ($null -ne $Body) {
            $params.ContentType = "application/json"
            $params.Body = ($Body | ConvertTo-Json -Compress)
        }
        return Invoke-WebRequest @params
    } catch {
        throw "Request failed: $Method $Uri. $($_.Exception.Message)"
    }
}

$health = Invoke-Raw "GET" "$GatewayUrl/actuator/health"
Assert-Status $health.StatusCode 200 "gateway health"

$login = Invoke-Raw "POST" "$GatewayUrl/auth/login" @{} @{ username = $Username; password = $Password }
Assert-Status $login.StatusCode 200 "login transport"
$loginBody = $login.Content | ConvertFrom-Json
if ($loginBody.code -ne 0 -or [string]::IsNullOrWhiteSpace($loginBody.data.accessToken)) { throw "login did not return an access token" }
$access = $loginBody.data.accessToken
$refresh = $loginBody.data.refreshToken
$auth = @{ Authorization = "Bearer $access" }

$missing = Invoke-Raw "GET" "$GatewayUrl/permissions"
Assert-Status $missing.StatusCode 401 "missing access token"

$internal = Invoke-Raw "GET" "$GatewayUrl/permissions/internal/users/1/permissions" $auth
Assert-Status $internal.StatusCode 404 "internal endpoint hidden"

$refreshBusiness = Invoke-Raw "GET" "$GatewayUrl/business/documents" @{ Authorization = "Bearer $refresh" }
Assert-Status $refreshBusiness.StatusCode 401 "refresh token rejected on business route"

$business = Invoke-Raw "GET" "$GatewayUrl/business/documents" $auth
Assert-Status $business.StatusCode 200 "business data route"

$admin = Invoke-Raw "GET" "$GatewayUrl/admin/users" $auth
Assert-Status $admin.StatusCode 200 "admin route for authorized user"

Write-Host "Security smoke test completed"
