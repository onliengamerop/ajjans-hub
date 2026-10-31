local SharedEnv = (type(getgenv) == "function" and getgenv()) or _G
local RunLockKey = "__AjjanStealAnEggRunning"
if SharedEnv[RunLockKey] then
    return
end

local RunToken = {}
SharedEnv[RunLockKey] = RunToken

local function ReleaseRunLock()
    if SharedEnv[RunLockKey] == RunToken then
        SharedEnv[RunLockKey] = nil
    end
end

if not game:IsLoaded() then
    game.Loaded:Wait()
end

local API_Origin = "https://ajjans-hub.pages.dev"
local Main_Loader_URL = "https://api.luarmor.net/files/v4/loaders/bd7ae88a118f9c741e628212fc9d499a.lua"
local Linkvertise_URL = API_Origin .. "/getkey"
local Premium_URL = "https://ajjans-hub.sellhub.cx/"
local Saved_Key_Path = "ajjanskey.txt"
local Legacy_Key_Path = "ajjan_custom_key.txt"
local Legacy_Luarmor_Key_Path = "ajjan_key.txt"
local Saved_Device_Path = "ajjan_device_id.txt"

local Players = game:GetService("Players")
local TweenService = game:GetService("TweenService")
local HttpService = game:GetService("HttpService")
local Player = Players.LocalPlayer
local PlayerGui = Player:WaitForChild("PlayerGui")

local Red = Color3.fromRGB(200, 30, 30)
local BrightRed = Color3.fromRGB(220, 40, 40)
local Green = Color3.fromRGB(40, 200, 40)
local Yellow = Color3.fromRGB(220, 180, 60)
local Orange = Color3.fromRGB(255, 180, 0)
local White = Color3.fromRGB(255, 255, 255)
local Dark = Color3.fromRGB(12, 12, 14)
local verified = false
local isCheckingKey = false
local DeviceID

-- Shared by the key screen and the independent main-script entry check.
local Luarmor_Script_ID = "bd7ae88a118f9c741e628212fc9d499a"
local Luarmor_Library_URL = "https://sdkapi-public.luarmor.net/library.lua"
local Luarmor_API
local Luarmor_Retry = { TIME_ERROR = true, UNKNOWN_ERROR = true, SECURITY_ERROR = true }

local function RequestLuarmorKeyStatus(key)
    if type(key) ~= "string" or #key ~= 32 or not key:match("^%w+$") then
        return { provider = "luarmor", code = "KEY_INVALID", message = "Enter your 32-character Luarmor key." }
    end
    local lastError = "Luarmor could not be reached. Please retry."
    for attempt = 1, 3 do
        if not Luarmor_API then
            local ok, library = pcall(function()
                local source = game:HttpGet(Luarmor_Library_URL)
                assert(type(source) == "string" and source ~= "", "The Luarmor library could not be downloaded.")
                local factory = loadstring(source)
                assert(type(factory) == "function", "The Luarmor library could not be compiled.")
                local api = factory()
                assert(type(api) == "table" and type(api.check_key) == "function", "Luarmor returned an incomplete library.")
                api.script_id = Luarmor_Script_ID
                return api
            end)
            if ok then Luarmor_API = library else lastError = "The Luarmor library is unavailable. Please retry." end
        end
        if Luarmor_API then
            local ok, status = pcall(Luarmor_API.check_key, key)
            if ok and type(status) == "table" and type(status.code) == "string" then
                if status.code == "KEY_VALID" and type(status.data) ~= "table" then
                    return { provider = "luarmor", code = "SECURITY_ERROR", message = "Luarmor returned an incomplete verification. Please retry." }
                end
                if not Luarmor_Retry[status.code] or attempt == 3 then
                    return { provider = "luarmor", code = status.code, message = status.message, data = status.data }
                end
                lastError = "Luarmor could not verify this request. Please retry."
            else
                lastError = "Luarmor returned an unreadable verification. Please retry."
            end
        end
        if attempt < 3 then task.wait(attempt) end
    end
    return { provider = "luarmor", code = "LUARMOR_UNAVAILABLE", message = lastError }
end


local function CopyToClipboard(text)
    local fn = setclipboard or toclipboard or (syn and syn.write_clipboard) or (Clipboard and Clipboard.set)
    if type(fn) ~= "function" then return false end
    return (pcall(fn, text))
end
local function CleanKey(raw)
    local key = tostring(raw or ""):gsub("%s", "")
    if key:upper():sub(1, 7) == "AJJANS-" then return key:upper() end
    return key
end
local function SaveKey(key)
    if type(writefile) ~= "function" or type(readfile) ~= "function" or type(isfile) ~= "function" then
        return false, "This executor needs file access to save ajjanskey.txt."
    end
    local ok = pcall(function()
        writefile(Saved_Key_Path, key)
        assert(isfile(Saved_Key_Path) and CleanKey(readfile(Saved_Key_Path)) == key, "Key could not be saved.")
    end)
    if not ok then return false, "Could not save ajjanskey.txt. Check your executor's file access and retry." end
    return true
end
local function ClearSavedKey()
    pcall(function()
        if type(isfile) == "function" and isfile(Saved_Key_Path) then
            if type(delfile) == "function" then delfile(Saved_Key_Path) else writefile(Saved_Key_Path, "") end
        end
    end)
end
local function ReadSavedKey()
    local key
    local explicit = SharedEnv.script_key or _G.script_key or script_key
    if type(explicit) == "string" and #CleanKey(explicit) == 32 and CleanKey(explicit):match("^%w+$") then return CleanKey(explicit) end
    for _, path in ipairs({ Saved_Key_Path, Legacy_Key_Path, Legacy_Luarmor_Key_Path }) do
        pcall(function()
            if type(isfile) == "function" and isfile(path) then key = CleanKey(readfile(path)) end
        end)
        if key and key ~= "" then break end
    end
    if key and key ~= "" then return key end
    return nil
end
local function SetGlobalKey(key, provider)
    local ajjansKey = provider == "ajjans" and key or nil
    local luarmorKey = provider == "luarmor" and key or nil
    SharedEnv.Ajjan_Key = ajjansKey
    SharedEnv.script_key = luarmorKey
    _G.Ajjan_Key = ajjansKey
    _G.script_key = luarmorKey
    script_key = luarmorKey
end
local StatusMessages = {
    KEY_EXPIRED = "This key expired. Complete the tasks on the key page to get a new key.",
    KEY_BANNED = "This key is revoked. Contact support if this is a mistake.",
    KEY_HWID_LOCKED = "Key is linked to another device. Contact support for a reset.",
    KEY_INCORRECT = "Wrong or deleted key.",
    KEY_INVALID = "Enter an AJJANS key or your 32-character Luarmor key.",
    SCRIPT_ID_INVALID = "The Luarmor script ID is invalid. Contact support.",
    SCRIPT_ID_INCORRECT = "This Luarmor script was not found. Contact support.",
    TIME_ERROR = "Luarmor could not verify your device time. Retry after syncing your clock.",
    UNKNOWN_ERROR = "Luarmor is temporarily unavailable. Please retry.",
    SECURITY_ERROR = "Luarmor could not verify this request. Please retry.",
    LUARMOR_UNAVAILABLE = "Luarmor is temporarily unavailable. Please retry.",
    DEVICE_INVALID = "Could not identify this device. Try a supported executor.",
    SERVICE_UNAVAILABLE = "Ajjan's key server is temporarily unavailable. Please retry.",
    RATE_LIMITED = "Too many attempts. Wait a minute and retry.",
    INVALID_EXECUTOR = "This executor needs an HTTP request function and a stable device ID.",
    SESSION_INVALID = "Your verification session expired. Press Verify Key again.",
    SCRIPT_UNAVAILABLE = "The game script is temporarily unavailable. Please retry shortly."
}
local ClearSavedOn = { KEY_BANNED = true, KEY_INCORRECT = true, KEY_INVALID = true }

local function GetDeviceID()
    if DeviceID then return DeviceID end
    local hardwareID = gethwid or get_hwid
    if type(hardwareID) == "function" then
        local ok, value = pcall(hardwareID)
        if ok and type(value) == "string" and #value >= 8 and #value <= 256 then DeviceID = value; return value end
    end
    if type(isfile) ~= "function" or type(readfile) ~= "function" or type(writefile) ~= "function" then
        return nil, StatusMessages.INVALID_EXECUTOR
    end
    local ok, value = pcall(function()
        if isfile(Saved_Device_Path) then
            local stored = readfile(Saved_Device_Path)
            if type(stored) == "string" and #stored >= 8 and #stored <= 256 then return stored end
        end
        local generated = HttpService:GenerateGUID(false)
        writefile(Saved_Device_Path, generated)
        assert(readfile(Saved_Device_Path) == generated, "Could not save device ID.")
        return generated
    end)
    if not ok then return nil, "Could not save your device ID: " .. tostring(value) end
    DeviceID = value
    return DeviceID
end
local function SendRequest(path, body, extraHeaders)
    local send = request or http_request or (type(syn) == "table" and syn.request) or (type(http) == "table" and http.request) or (type(fluxus) == "table" and fluxus.request)
    if type(send) ~= "function" then return nil, StatusMessages.INVALID_EXECUTOR end
    local headers = { ["Content-Type"] = "application/json", ["Accept"] = "application/json, text/plain" }
    for name, value in pairs(extraHeaders or {}) do headers[name] = value end
    local ok, response = pcall(send, { Url = API_Origin .. path, Method = "POST", Headers = headers, Body = HttpService:JSONEncode(body or {}) })
    if not ok then return nil, tostring(response) end
    if type(response) ~= "table" or type(response.Body) ~= "string" or not tonumber(response.StatusCode) then return nil, "The server returned an incomplete response." end
    return response
end
local function RequestAjjansKeyStatus(key)
    local device, deviceError = GetDeviceID()
    if not device then return { code = "INVALID_EXECUTOR", message = deviceError } end
    local lastError = "No response from Ajjan's server."
    for attempt = 1, 3 do
        local response, err = SendRequest("/api/keys/authenticate", { key = key, device = device })
        if response then
            local decoded, status = pcall(function() return HttpService:JSONDecode(response.Body) end)
            if decoded and type(status) == "table" and type(status.code) == "string" then
                if status.code == "KEY_VALID" and (tonumber(response.StatusCode) ~= 200 or status.ok ~= true or type(status.session) ~= "string" or #status.session ~= 64 or not status.session:match("^%x+$")) then
                    return nil, "The server did not authorize this key."
                end
                if status.code ~= "SERVICE_UNAVAILABLE" or attempt == 3 then status.provider = "ajjans"; return status end
                lastError = status.message
            else lastError = "The key server returned an unreadable response." end
        else lastError = err end
        if attempt < 3 then task.wait(attempt) end
    end
    return nil, lastError
end
local function RequestKeyStatus(key)
    if key:upper():sub(1, 7) == "AJJANS-" then return RequestAjjansKeyStatus(key) end
    local premium = RequestLuarmorKeyStatus(key)
    if premium.code == "KEY_VALID" then return premium end
    -- Only legacy Ajjans keys share Luarmor's 32-character format.
    -- A known Luarmor denial keeps its original expiry/HWID/ban message.
    if premium.code == "KEY_EXPIRED" or premium.code == "KEY_BANNED" or premium.code == "KEY_HWID_LOCKED" then return premium end
    if #key == 32 and key:match("^%x+$") then
        local legacy, err = RequestAjjansKeyStatus(key)
        if legacy and legacy.code ~= "KEY_INCORRECT" and legacy.code ~= "KEY_INVALID" then return legacy end
        if not legacy and (premium.code == "KEY_INCORRECT" or premium.code == "KEY_INVALID") then
            return nil, err
        end
    end
    return premium
end
local function FetchHub()
    local ok, source = pcall(function() return game:HttpGet(Main_Loader_URL) end)
    if not ok or type(source) ~= "string" or source == "" then return nil, "Could not download the main loader. Please retry." end
    local factory, compileError = loadstring(source)
    if type(factory) ~= "function" then return nil, "Could not compile the main loader: " .. tostring(compileError) end
    return factory
end


-- Four text-free images; all wording and controls are Roblox-native.
-- For now they load from the executor workspace (workspace/AjjanKeySystem/*.png) via getcustomasset.
-- Once uploaded, put "rbxassetid://..." in ASSET_IDS and that wins over the local file.
local ASSET_IDS = {
    Background = "", -- main_ui_background.png
    VerifyButton = "", -- button_verify_1024.png
    GetKeyButton = "", -- button_get_key_1024.png
    BuyButton = "", -- button_buy_premium_1024.png
}
local ASSET_FILES = {
    Background = "AjjanKeySystem/main_ui_background.png",
    VerifyButton = "AjjanKeySystem/button_verify_1024.png",
    GetKeyButton = "AjjanKeySystem/button_get_key_1024.png",
    BuyButton = "AjjanKeySystem/button_buy_premium_1024.png",
}
local ASSETS = {}
for name, file in pairs(ASSET_FILES) do
    local id = ASSET_IDS[name]
    if id == "" and getcustomasset and isfile and isfile(file) then
        local ok, result = pcall(getcustomasset, file)
        id = ok and result or ""
    end
    if id == "" then warn("[AjjanKeySystem] missing image: " .. file) end
    ASSETS[name] = id
end
local MAX_WIDTH = 880 -- Change this one value to adjust the desktop window.
local SCREEN_FILL = 0.92 -- Share of the screen height the window may use on desktop.
local ART_W, ART_H = 1122, 1402 -- Pixel size of main_ui_background.png; every coordinate below uses it.
local UserInputService = game:GetService("UserInputService")
local existing = PlayerGui:FindFirstChild("AjjanKeySystem")
if existing then existing:Destroy() end
local function New(className, parent, props): any
    local object: any = Instance.new(className)
    for key, value in pairs(props or {}) do object[key] = value end
    object.Parent = parent
    return object
end
local ScreenGui = New("ScreenGui", PlayerGui, {
    Name = "AjjanKeySystem", ResetOnSpawn = false, DisplayOrder = 2147483647,
    ScreenInsets = Enum.ScreenInsets.CoreUISafeInsets,
    ClipToDeviceSafeArea = true, ZIndexBehavior = Enum.ZIndexBehavior.Sibling,
})
ScreenGui.AncestryChanged:Connect(function(_, parent)
    if not parent and not verified then ReleaseRunLock() end
end)
local Root = New("Frame", ScreenGui, {BackgroundTransparency = 1, Size = UDim2.fromScale(1, 1)})
local Scroll = New("ScrollingFrame", Root, {
    Name = "Window", AnchorPoint = Vector2.new(0.5, 0.5), Position = UDim2.fromScale(0.5, 0.5),
    BackgroundTransparency = 1, BorderSizePixel = 0, ScrollBarThickness = 3,
    ScrollBarImageColor3 = BrightRed, ScrollingDirection = Enum.ScrollingDirection.Y,
    CanvasSize = UDim2.fromOffset(0, 0), ZIndex = 2,
})
local MainFrame = New("Frame", Scroll, {Name = "Content", BackgroundTransparency = 1, ZIndex = 2})
local Background = New("ImageLabel", MainFrame, {
    Name = "MainArtwork", BackgroundTransparency = 1, Image = ASSETS.Background,
    Size = UDim2.fromScale(1, 1), ScaleType = Enum.ScaleType.Stretch, ZIndex = 2,
})
local placements = {}
local isPhone = false
local function Animate(object,seconds,props,style,direction)
    local tween=TweenService:Create(object,TweenInfo.new(seconds,style or Enum.EasingStyle.Quart,direction or Enum.EasingDirection.Out),props)
    tween:Play()
    return tween
end
local function Loop(object,seconds,props,style,reverses)
    local tween=TweenService:Create(object,TweenInfo.new(seconds,style or Enum.EasingStyle.Sine,Enum.EasingDirection.InOut,-1,reverses ~= false),props)
    tween:Play()
    return tween
end
local function Place(object, x, y, w, h, fontSize, minSize, minHeight)
    table.insert(placements, {object=object, x=x, y=y, w=w, h=h, font=fontSize, minFont=minSize, minHeight=minHeight})
    return object
end
local function Label(name, text, x, y, w, h, size, minSize, bold, color)
    return Place(New("TextLabel", MainFrame, {
        Name = name, BackgroundTransparency = 1, Text = text,
        TextColor3 = color or White, Font = bold and Enum.Font.GothamBold or Enum.Font.Gotham,
        TextXAlignment = Enum.TextXAlignment.Left, TextYAlignment = Enum.TextYAlignment.Center,
        TextWrapped = true, ZIndex = 6,
    }), x, y, w, h, size, minSize)
end
-- Desktop drag handle across the header artwork; buttons sit above it and keep their clicks.
local DragHandle = Place(New("Frame", MainFrame, {Name = "DragHandle", BackgroundTransparency = 1, Active = true, ZIndex = 3}), 0, 0, ART_W, 400)
local Title = Label("Title", '<font color="#FF4147">Ajjan Hub</font> • Key System', 445,174,560,68,50,14,true)
Title.RichText = true
Title.Font = Enum.Font.GothamBlack
Title.TextStrokeColor3 = Color3.fromRGB(255, 40, 50)
Title.TextStrokeTransparency = 0.85
local Subtitle = Label("Subtitle", "P R E M I U M   S C R I P T   H U B",445,246,500,32,23,9,false,Color3.fromRGB(188,188,188))
local FeatureTitles, FeatureSubs = {}, {}
for i, data in ipairs({{497,88,"Powerful","Scripts"},{658,120,"Safe & Secure","Key System"},{850,100,"Premium","Experience"}}) do
    FeatureTitles[i] = Label("Feature"..i,data[3],data[1],297,data[2],27,18,9,true)
    FeatureSubs[i] = Label("FeatureHint"..i,data[4],data[1],326,data[2],26,17,8,false,Color3.fromRGB(174,174,174))
end
local KeyLabel = Label("KeyHeading","KEY VERIFICATION",268,450,650,35,26,12,true)
local KeyHint = Label("KeyHint","Enter your key below to access Ajjan Hub.",268,490,650,35,22,10,false,Color3.fromRGB(181,181,181))
-- Soft red glow behind the key field that lights up while it has focus.
local InputGlow = Place(New("Frame",MainFrame,{Name="InputGlow",BackgroundTransparency=1,ZIndex=5}),154,541,820,77)
New("UICorner",InputGlow,{CornerRadius=UDim.new(0.13,0)})
local InputStroke = New("UIStroke",InputGlow,{Color=BrightRed,Thickness=2,Transparency=1})
local TextBox = Place(New("TextBox",MainFrame,{
    Name="KeyInput", BackgroundTransparency=1, Text="", PlaceholderText="AJJANS-XXXX-XXXX-XXXX",
    PlaceholderColor3=Color3.fromRGB(155,150,153), TextColor3=White, ClearTextOnFocus=false,
    TextXAlignment=Enum.TextXAlignment.Left, Font=Enum.Font.Gotham,
    TextWrapped=false, MultiLine=false, ClipsDescendants=true, ZIndex=7,
}),178,544,620,73,27,12,30)
local KeyCounter = Label("KeyCounter","0/32",800,560,90,40,20,9,true,Color3.fromRGB(120,116,118))
KeyCounter.TextXAlignment = Enum.TextXAlignment.Right
local function HitButton(name,text,x,y,w,h,size,minSize)
    return Place(New("TextButton",MainFrame,{
        Name=name,BackgroundTransparency=1,Text=text,TextColor3=White,
        Font=Enum.Font.GothamBold,TextWrapped=true,AutoButtonColor=false,ZIndex=7,
    }),x,y,w,h,size,minSize,30)
end
local CloseButton = HitButton("Close","×",970,92,60,60,40,20)
CloseButton.TextColor3 = BrightRed
local CopyButton = HitButton("CopyKey","",901,552,60,56,20,12)
-- Button art is measured in the original PNG's pixels (W x H): the button body sits at left/top/inkW/inkH,
-- the baked icon ends at iconEnd, the baked arrow starts at arrowStart, and the plain strip
-- sliceFrom..sliceTo is the only part that stretches, so icons and arrows never get squashed.
-- The PNGs are loaded at 1024px wide (Roblox downsizes uploads to that too), hence BUTTON_PX.
-- ScaleType.Slice draws these wrong, so each button is three ImageRect crops instead.
local BUTTON_PX = 1024
local BUTTON_ART = {
    Verify = {W=2167,H=725,left=88,top=176,inkW=1992,inkH=344,iconEnd=410,arrowStart=1770,sliceFrom=700,sliceTo=1150},
    GetKey = {W=2071,H=759,left=86,top=210,inkW=1898,inkH=306,iconEnd=405,arrowStart=1710,sliceFrom=940,sliceTo=1000},
    BuyPremium = {W=2022,H=778,left=52,top=216,inkW=1918,inkH=318,iconEnd=345,arrowStart=1710,sliceFrom=760,sliceTo=1100},
}
-- Green "copied" ripple, pop and sweep, after the website's copy button; an orange ripple when it fails.
local CopyGreen = Color3.fromRGB(43, 217, 107)
local function CopyBurst(target, zoom, ok)
    if not target.Parent then return end
    if zoom then
        zoom.Scale = 0.94
        Animate(zoom, 0.35, {Scale = 1}, Enum.EasingStyle.Back)
    end
    local corner = target:FindFirstChildOfClass("UICorner")
    local radius = corner and corner.CornerRadius or UDim.new(0.12, 0)
    local ring = New("Frame", target, {
        Name = "CopiedRing", BackgroundTransparency = 1, AnchorPoint = Vector2.new(0.5, 0.5),
        Position = UDim2.fromScale(0.5, 0.5), Size = UDim2.fromScale(1, 1), ZIndex = 8,
    })
    New("UICorner", ring, {CornerRadius = radius})
    local ringStroke = New("UIStroke", ring, {Color = ok and CopyGreen or Orange, Thickness = 3, Transparency = 0.2})
    Animate(ring, 0.7, {Size = UDim2.new(1, 32, 1, 32)})
    Animate(ringStroke, 0.7, {Transparency = 1, Thickness = 1})
    task.delay(0.72, function() ring:Destroy() end)
    if not ok then return end
    local sweep = New("Frame", target, {
        Name = "CopiedSweep", BackgroundColor3 = CopyGreen, BackgroundTransparency = 0.55,
        BorderSizePixel = 0, Size = UDim2.fromScale(1, 1), ZIndex = 8,
    })
    New("UICorner", sweep, {CornerRadius = radius})
    local sweepGradient = New("UIGradient", sweep, {
        Rotation = 15, Offset = Vector2.new(-1.1, 0),
        Transparency = NumberSequence.new({
            NumberSequenceKeypoint.new(0, 1), NumberSequenceKeypoint.new(0.36, 1),
            NumberSequenceKeypoint.new(0.5, 0.1),
            NumberSequenceKeypoint.new(0.64, 1), NumberSequenceKeypoint.new(1, 1),
        }),
    })
    Animate(sweepGradient, 0.9, {Offset = Vector2.new(1.1, 0)})
    task.delay(0.92, function() sweep:Destroy() end)
end
local ActionZooms = {}
local ActionLabels = {}
local lastPressed, lastPressedAt = nil, 0
local function Action(name,text,asset,x,y,w,h)
    local spec=BUTTON_ART[name]
    local k=BUTTON_PX/spec.W
    local group=Place(New("Frame",MainFrame,{Name=name.."Group",BackgroundTransparency=1,ZIndex=4}),x,y,w,h,nil,nil,30)
    local zoom=New("UIScale",group,{Scale=1})
    -- Three crops of the same PNG: fixed left cap (icon), stretchable middle, fixed right cap (arrow).
    local art = New("Frame",group,{Name=name.."Artwork",BackgroundTransparency=1,ZIndex=4})
    local pixelH=math.floor(spec.H*k+0.5)
    local function Piece(pieceName,from,to)
        return New("ImageLabel",art,{
            Name=pieceName,BackgroundTransparency=1,Image=asset,ScaleType=Enum.ScaleType.Stretch,
            ImageRectOffset=Vector2.new(math.floor(from*k),0),
            ImageRectSize=Vector2.new(math.floor(to*k)-math.floor(from*k),pixelH),ZIndex=4,
        })
    end
    local leftCap=Piece("Left",0,spec.sliceFrom)
    local middle=Piece("Middle",spec.sliceFrom,spec.sliceTo)
    local rightCap=Piece("Right",spec.sliceTo,spec.W)
    leftCap.ZIndex,rightCap.ZIndex=5,5
    local pieces={leftCap,middle,rightCap}
    -- A white band that sweeps across the button face now and then.
    local shine=New("Frame",group,{Name="Shine",BackgroundColor3=White,BackgroundTransparency=0.82,BorderSizePixel=0,Size=UDim2.fromScale(1,1),ZIndex=6})
    New("UICorner",shine,{CornerRadius=UDim.new(0.14,0)})
    local shineGradient=New("UIGradient",shine,{
        Rotation=20,Offset=Vector2.new(-1.2,0),
        Transparency=NumberSequence.new({
            NumberSequenceKeypoint.new(0,1),NumberSequenceKeypoint.new(0.42,1),
            NumberSequenceKeypoint.new(0.5,0),
            NumberSequenceKeypoint.new(0.58,1),NumberSequenceKeypoint.new(1,1),
        }),
    })
    local button=New("TextButton",group,{
        Name=name,BackgroundTransparency=1,Size=UDim2.fromScale(1,1),Text=text,TextColor3=White,
        Font=Enum.Font.GothamBold,TextWrapped=true,AutoButtonColor=false,ZIndex=7,
    })
    table.insert(placements,{object=button,font=32,minFont=12,fontOnly=true})
    local padding=New("UIPadding",button)
    -- Runs from Reflow with the unscaled size, so hover zoom never feeds back into the layout.
    placements[#placements-1].layout=function(gw,gh)
        local s=gh/spec.inkH
        local total=gw+(spec.W-spec.inkW)*s
        local leftW=spec.sliceFrom*s
        local rightFrom=spec.sliceTo
        local rightW=(spec.W-rightFrom)*s
        local gap=total-leftW-rightW
        if gap<0 then
            -- Box narrower than the art: squeezing pinches the border highlights into ticks,
            -- so cut a plain section out instead and let the two ends meet.
            rightW=total-leftW
            rightFrom=spec.W-rightW/s
            gap=0
        end
        rightCap.ImageRectOffset=Vector2.new(math.floor(rightFrom*k),0)
        rightCap.ImageRectSize=Vector2.new(math.floor(spec.W*k)-math.floor(rightFrom*k),pixelH)
        art.Position=UDim2.fromOffset(-spec.left*s,-spec.top*s)
        art.Size=UDim2.fromOffset(total,spec.H*s)
        leftCap.Size=UDim2.new(0,leftW,1,0)
        -- the middle tucks 1px under each cap so no hairline shows at the joins
        middle.Visible=gap>0
        middle.Position=UDim2.fromOffset(leftW-1,0)
        middle.Size=UDim2.new(0,gap+2,1,0)
        rightCap.Position=UDim2.fromOffset(total-rightW,0)
        rightCap.Size=UDim2.new(0,rightW,1,0)
        padding.PaddingLeft=UDim.new(0,(spec.iconEnd-spec.left)*s)
        padding.PaddingRight=UDim.new(0,(spec.left+spec.inkW-spec.arrowStart)*s)
    end
    -- When the label changes, the old text rises and fades out while the new text rises in from below.
    local shownText=button.Text
    button:GetPropertyChangedSignal("Text"):Connect(function()
        local old=shownText
        shownText=button.Text
        if old==shownText or (old:sub(1,8)=="Checking" and shownText:sub(1,8)=="Checking") then return end
        local ghost=New("TextLabel",group,{
            Name="OutgoingLabel",BackgroundTransparency=1,Size=UDim2.fromScale(1,1),Text=old,
            TextColor3=White,Font=button.Font,TextSize=button.TextSize,TextWrapped=true,ZIndex=7,
        })
        New("UIPadding",ghost,{PaddingLeft=padding.PaddingLeft,PaddingRight=padding.PaddingRight})
        Animate(ghost,0.28,{Position=UDim2.fromOffset(0,-12),TextTransparency=1})
        task.delay(0.3,function() ghost:Destroy() end)
        button.Position=UDim2.fromOffset(0,12)
        button.TextTransparency=1
        Animate(button,0.42,{Position=UDim2.fromOffset(0,0),TextTransparency=0},Enum.EasingStyle.Back)
    end)
    -- The game scripts recolour these labels for the old flat buttons; on the artwork they stay white.
    button:GetPropertyChangedSignal("TextColor3"):Connect(function()
        if button.TextColor3~=White then button.TextColor3=White end
    end)
    ActionZooms[button]=zoom
    ActionLabels[button]=text
    button.Activated:Connect(function() lastPressed,lastPressedAt=button,os.clock() end)
    local hovering=false
    local activeTween=nil
    local function Feedback(size,tint)
        if activeTween then activeTween:Cancel() end
        activeTween=Animate(zoom,0.16,{Scale=size},Enum.EasingStyle.Back)
        for _,piece in ipairs(pieces) do Animate(piece,0.16,{ImageColor3=tint}) end
    end
    local function Sweep()
        shineGradient.Offset=Vector2.new(-1.2,0)
        Animate(shineGradient,0.7,{Offset=Vector2.new(1.2,0)},Enum.EasingStyle.Sine,Enum.EasingDirection.InOut)
    end
    button.MouseEnter:Connect(function() hovering=true;if button.Active then Feedback(1.035,Color3.fromRGB(255,225,225));Sweep() end end)
    button.MouseLeave:Connect(function() hovering=false;Feedback(1,White) end)
    button.MouseButton1Down:Connect(function() if button.Active then Feedback(0.96,Color3.fromRGB(255,190,190)) end end)
    button.MouseButton1Up:Connect(function() Feedback(hovering and 1.035 or 1,White) end)
    button.Activated:Connect(function() Feedback(1,White) end)
    return button,pieces,Sweep
end
-- Align the visible button inside its transparent canvas without pixel-coordinate cropping.
local CheckButton, VerifyArt, VerifySweep = Action("Verify","Verify Key",ASSETS.VerifyButton,155,654,466,85)
local GetKeyButton = Action("GetKey","Get Key",ASSETS.GetKeyButton,635,654,338,85)
local OrText=Label("DividerText","OR",526,765,68,35,24,11,true,BrightRed)
OrText.TextXAlignment=Enum.TextXAlignment.Center
local Tag=Place(New("Frame",MainFrame,{BackgroundColor3=Red,BorderSizePixel=0,ZIndex=5}),173,840,180,40)
New("UICorner",Tag,{CornerRadius=UDim.new(0,5)})
local TagText=Label("PremiumTag","PREMIUM",183,840,160,40,22,10,true)
TagText.TextXAlignment=Enum.TextXAlignment.Center
local PremiumTitle=Label("PremiumHeading",'Get <font color="#FF4147">Permanent Access</font>',170,907,580,64,47,15,true)
PremiumTitle.RichText=true
PremiumTitle.Font=Enum.Font.GothamBlack
local PremiumDesc=Label("PremiumDescription","One-time purchase, permanent access.\nNo checkpoints, no daily resets.",175,978,500,60,24,10,false,Color3.fromRGB(185,185,185))
local BuyPremiumButton, _, BuySweep=Action("BuyPremium","Buy Permanent Key",ASSETS.BuyButton,155,1052,594,88)
-- Green wash over the status bar once the key is accepted.
-- Sits inside the status bar's border in the artwork (x 156-998, y 1180-1276) and fades out to the right.
local StatusGlow=Place(New("Frame",MainFrame,{Name="StatusGlow",BackgroundColor3=Green,BackgroundTransparency=1,BorderSizePixel=0,ZIndex=5}),160,1184,834,88)
New("UICorner",StatusGlow,{CornerRadius=UDim.new(0.14,0)})
New("UIGradient",StatusGlow,{Transparency=NumberSequence.new({
    NumberSequenceKeypoint.new(0,0.2),NumberSequenceKeypoint.new(0.45,0.75),NumberSequenceKeypoint.new(1,1),
})})
local StatusDot=Place(New("Frame",MainFrame,{Name="StatusDot",BackgroundColor3=Red,BorderSizePixel=0,ZIndex=6}),165,1213,30,30)
New("UICorner",StatusDot,{CornerRadius=UDim.new(1,0)})
local DotScale=New("UIScale",StatusDot,{Scale=1})
local StatusRing=Place(New("Frame",MainFrame,{Name="StatusRing",BackgroundTransparency=1,ZIndex=6}),152,1200,56,56)
New("UICorner",StatusRing,{CornerRadius=UDim.new(1,0)})
local StatusStroke=New("UIStroke",StatusRing,{Color=Red,Thickness=2,Transparency=0.15})
local RingGradient=New("UIGradient",StatusStroke,{
    Transparency=NumberSequence.new({NumberSequenceKeypoint.new(0,0),NumberSequenceKeypoint.new(0.55,0.85),NumberSequenceKeypoint.new(1,0)}),
})
local StatusText=Label("Status","Enter your key to verify",230,1198,550,45,26,12,true,Red)
local StatusHint=Label("StatusHint","Use a free key or choose permanent access.",230,1243,545,30,19,10,false,Color3.fromRGB(185,185,185))
StatusText.TextTruncate=Enum.TextTruncate.AtEnd
local StatusTextPad=New("UIPadding",StatusText)
local StatusHintPad=New("UIPadding",StatusHint)
local function Reflow()
    local area=Root.AbsoluteSize
    if area.X<1 or area.Y<1 then return end
    local phone=area.X<520
    isPhone=phone
    DragHandle.Active=not phone -- On phones the header must not swallow scroll touches.
    local margin=phone and 12 or 24
    local width=math.min(MAX_WIDTH,math.max(1,area.X-margin*2))
    -- On desktop the whole window must fit on screen, so height decides the width; the art keeps its exact proportions.
    if not phone then width=math.min(width,math.max(1,area.Y*SCREEN_FILL)*ART_W/ART_H) end
    local scale=width/ART_W
    local height=ART_H*scale
    local viewportHeight=math.min(height,math.max(1,area.Y-margin*2))
    Scroll.Size=UDim2.fromOffset(width,viewportHeight)
    Scroll.CanvasSize=UDim2.fromOffset(0,height)
    Scroll.ScrollingEnabled=height>viewportHeight+1
    Scroll.ScrollBarThickness=Scroll.ScrollingEnabled and 3 or 0
    Scroll.Position=UDim2.fromScale(0.5,0.5)
    MainFrame.Size=UDim2.fromOffset(width,height)
    for _,p in ipairs(placements) do
        if not p.fontOnly then
            local h=math.max(p.h*scale,p.minHeight or 0)
            p.object.Position=UDim2.fromOffset(p.x*scale,p.y*scale+(p.h*scale-h)/2)
            p.object.Size=UDim2.fromOffset(p.w*scale,h)
            if p.layout then p.layout(p.w*scale,h) end
        end
        if p.font then p.object.TextSize=math.max(p.minFont or 1,p.font*scale) end
    end
    Title.Text=phone and '<font color="#FF4147">Ajjan Hub</font>\nKey System' or '<font color="#FF4147">Ajjan Hub</font> • Key System'
    if phone then Title.Position=UDim2.fromOffset(445*scale,164*scale);Title.Size=UDim2.fromOffset(526*scale,88*scale) end
    Subtitle.Visible=not phone
    local short={"Fast","Safe","Pro"}
    local full={"Powerful","Safe & Secure","Premium"}
    for i,label in ipairs(FeatureTitles) do
        label.Text=phone and short[i] or full[i]
        FeatureSubs[i].Visible=not phone
    end
    if phone then
        for i,x in ipairs({497,658,850}) do
            FeatureTitles[i].Position=UDim2.fromOffset(x*scale,308*scale)
            FeatureTitles[i].Size=UDim2.fromOffset(({88,120,100})[i]*scale,32*scale)
        end
    end
    KeyHint.Text=phone and "Enter your key below." or "Enter your key below to access Ajjan Hub."
    TextBox.PlaceholderText=phone and "Paste key..." or "AJJANS-XXXX-XXXX-XXXX"
    KeyCounter.Visible=not phone
    PremiumTitle.Text=phone and 'Get Permanent\n<font color="#FF4147">Access</font>' or 'Get <font color="#FF4147">Permanent Access</font>'
    if phone then PremiumTitle.Position=UDim2.fromOffset(170*scale,900*scale);PremiumTitle.Size=UDim2.fromOffset(535*scale,86*scale) end
    PremiumDesc.Text=phone and "One-time purchase.\nNo daily resets." or "One-time purchase, permanent access.\nNo checkpoints, no daily resets."
    StatusHint.Visible=not phone
    if phone then StatusText.Size=UDim2.fromOffset(550*scale,68*scale) end
    local maxScroll=math.max(0,height-viewportHeight)
    Scroll.CanvasPosition=Vector2.new(0,math.clamp(Scroll.CanvasPosition.Y,0,maxScroll))
end
Root:GetPropertyChangedSignal("AbsoluteSize"):Connect(Reflow)
Reflow()
task.defer(Reflow)
-- Messages show in the status bar under the red dot. A message holds for a few seconds,
-- then the bar falls back to the last SetStatus; SetStatus calls during the hold are kept for that.
local DefaultHint="Use a free key or choose permanent access."
local StatusBase={text="Enter your key to verify",color=Red}
local StatusHoldUntil,StatusSerial=0,0
local function IsGood(color) return color==Green or color==CopyGreen end
local function ShowStatus(text,color,hint)
    local ok=IsGood(color)
    StatusText.Text=text;StatusText.TextColor3=color;StatusDot.BackgroundColor3=color
    StatusHint.Text=hint or (ok and "Your key is valid. Unlocking Ajjan Hub..." or DefaultHint)
    -- text rises into place, the dot pops, ring and glow follow the colour
    StatusText.TextTransparency,StatusHint.TextTransparency=1,1
    StatusHintPad.PaddingTop=UDim.new(0,10)
    Animate(StatusText,0.3,{TextTransparency=0})
    local centre=(StatusHint.Text=="" and StatusHint.Visible) and 30*MainFrame.AbsoluteSize.X/ART_W or 0
    StatusTextPad.PaddingTop=UDim.new(0,centre+10)
    Animate(StatusTextPad,0.4,{PaddingTop=UDim.new(0,centre)},Enum.EasingStyle.Back)
    task.delay(0.06,function()
        Animate(StatusHint,0.3,{TextTransparency=0})
        Animate(StatusHintPad,0.4,{PaddingTop=UDim.new(0,0)},Enum.EasingStyle.Back)
    end)
    Animate(StatusStroke,0.25,{Color=color,Transparency=ok and 0 or 0.15})
    Animate(StatusGlow,0.4,{BackgroundTransparency=ok and 0.8 or 1})
    DotScale.Scale=1.6
    Animate(DotScale,0.4,{Scale=1},Enum.EasingStyle.Back)
end
local function SetStatus(text,color)
    StatusBase={text=text,color=color}
    if os.clock()<StatusHoldUntil then return end
    ShowStatus(text,color)
end
local function Notify(message,color)
    if not ScreenGui.Parent then return end
    color=color or Red
    if color==White then color=Color3.fromRGB(235,235,235) end
    -- drop leading emoji, then split "Title! rest of the sentence" into the two status lines
    local clean=message:gsub("^[^%w]+","")
    local title,hint=clean:match("^(.-[%.!:])%s+(.+)$")
    if not title then title,hint=clean,"" end
    if title:sub(-1)==":" then title=title:sub(1,-2) end
    StatusSerial+=1
    local id=StatusSerial
    StatusHoldUntil=os.clock()+3.5
    ShowStatus(title,color,hint)
    -- Get Key / Buy copy their links in the game script; play the copied effect on whichever was just pressed.
    if lastPressed and os.clock()-lastPressedAt<1.5 then
        local pressed=lastPressed
        local lower=message:lower()
        local ok=lower:find("copied")~=nil
        if ok or lower:find("unsupported") or lower:find("fail") then
            lastPressed=nil
            CopyBurst(pressed.Parent,ActionZooms[pressed],ok)
            -- swap the label unless the game script already changed it itself
            local label=ActionLabels[pressed]
            if pressed.Text==label then
                pressed.Text=ok and "✓ Copied" or "Copy Failed"
                task.delay(2,function() if pressed.Parent then pressed.Text=label end end)
            end
        end
    end
    task.delay(3.5,function()
        if id==StatusSerial and StatusText.Parent then
            StatusHoldUntil=0
            ShowStatus(StatusBase.text,StatusBase.color)
        end
    end)
end
local LoadingPulse=nil
local IdlePulse=Loop(StatusDot,1.4,{BackgroundTransparency=0.45})
local RingSpin=Loop(RingGradient,2.4,{Rotation=360},Enum.EasingStyle.Linear,false)
local function SetBusy(busy)
    isCheckingKey=busy
    if busy then StatusHoldUntil=0 end
    CheckButton.Active=not busy
    CheckButton.Text=busy and "Checking" or "Verify Key"
    for _,piece in ipairs(VerifyArt) do piece.ImageTransparency=busy and 0.2 or 0 end
    CloseButton.Active=not busy
    CloseButton.TextTransparency=busy and 0.5 or 0
    if LoadingPulse then LoadingPulse:Cancel();LoadingPulse=nil end
    RingSpin:Cancel()
    RingSpin=Loop(RingGradient,busy and 0.8 or 2.4,{Rotation=RingGradient.Rotation+360},Enum.EasingStyle.Linear,false)
    StatusDot.BackgroundTransparency=0
    if busy then
        IdlePulse:Pause()
        LoadingPulse=Loop(StatusDot,0.45,{BackgroundTransparency=0.7})
        task.spawn(function()
            local dots=0
            while isCheckingKey and CheckButton.Parent do
                dots=dots%3+1
                CheckButton.Text="Checking"..string.rep(".",dots)
                task.wait(0.35)
            end
        end)
    else
        IdlePulse:Play()
    end
end
local function CloseWindow()
    if isCheckingKey or verified or not ScreenGui.Parent then return end
    CloseButton.Active=false
    Animate(Scroll:FindFirstChildOfClass("UIScale"),0.2,{Scale=0.9},Enum.EasingStyle.Quart,Enum.EasingDirection.In)
    for _,object in ipairs(MainFrame:GetDescendants()) do
        if object:IsA("ImageLabel") then Animate(object,0.2,{ImageTransparency=1})
        elseif object:IsA("TextLabel") or object:IsA("TextButton") or object:IsA("TextBox") then Animate(object,0.15,{TextTransparency=1}) end
    end
    task.delay(0.22,function() if ScreenGui.Parent then ScreenGui:Destroy() end end)
end
CloseButton.Activated:Connect(CloseWindow)
CloseButton.MouseEnter:Connect(function() if CloseButton.Active then Animate(CloseButton,0.2,{Rotation=90,TextColor3=White},Enum.EasingStyle.Back) end end)
CloseButton.MouseLeave:Connect(function() Animate(CloseButton,0.2,{Rotation=0,TextColor3=BrightRed},Enum.EasingStyle.Back) end)
ScreenGui.Destroying:Connect(function()
    if LoadingPulse then LoadingPulse:Cancel() end
    IdlePulse:Cancel();RingSpin:Cancel()
end)
-- Covers the clipboard glyph baked into the artwork so a check mark can replace it after pasting.
local CopyCover=Place(New("Frame",MainFrame,{Name="PastedCover",BackgroundColor3=White,BackgroundTransparency=1,BorderSizePixel=0,ZIndex=6}),910,558,44,46)
New("UIGradient",CopyCover,{Rotation=90,Color=ColorSequence.new(Color3.fromRGB(31,30,31),Color3.fromRGB(22,22,22))})
local CopyCheck=New("TextLabel",CopyCover,{
    Name="Check",BackgroundTransparency=1,AnchorPoint=Vector2.new(0.5,0.5),Position=UDim2.fromScale(0.5,0.5),
    Size=UDim2.fromScale(1,1),Text="✓",TextScaled=true,Font=Enum.Font.GothamBlack,
    TextColor3=CopyGreen,TextTransparency=1,ZIndex=6,
})
local CheckScale=New("UIScale",CopyCheck,{Scale=0.4})
local PasteSerial=0
local function PlayPasted()
    PasteSerial+=1
    local id=PasteSerial
    CopyBurst(InputGlow,nil,true)
    -- clipboard glyph out, check mark spins and pops in, field text flashes green
    CopyCheck.Rotation=-25;CheckScale.Scale=0.4
    Animate(CopyCover,0.25,{BackgroundTransparency=0})
    Animate(CopyCheck,0.4,{TextTransparency=0,Rotation=0},Enum.EasingStyle.Back)
    Animate(CheckScale,0.4,{Scale=1},Enum.EasingStyle.Back)
    TextBox.TextColor3=Color3.fromRGB(184,245,207)
    Animate(TextBox,0.9,{TextColor3=White},Enum.EasingStyle.Quad)
    task.delay(1.6,function()
        if id~=PasteSerial or not CopyCover.Parent then return end
        Animate(CopyCheck,0.3,{TextTransparency=1,Rotation=25})
        Animate(CheckScale,0.3,{Scale=0.4})
        Animate(CopyCover,0.3,{BackgroundTransparency=1})
    end)
end
local function FlashField(color)
    InputStroke.Color=color;InputStroke.Transparency=0
    Animate(InputStroke,0.6,{Transparency=1})
    task.delay(0.6,function() InputStroke.Color=BrightRed end)
end
local function LooksLikeKey(text)
    return (#text == 32 and text:match("^%w+$") ~= nil)
        or text:upper():match("^AJJANS%-%w%w%w%w%-%w%w%w%w%-%w%w%w%w$") ~= nil
end
-- Reading the clipboard: a getclipboard-style function when the executor has one, otherwise a real
-- Ctrl+V into the focused field (keypress), read back and restored so nothing flashes on screen.
local ReadClipboard=getclipboard or fromclipboard or (Clipboard and Clipboard.get)
local pasting=false
local function NativePaste()
    if type(keypress)~="function" or type(keyrelease)~="function" then return nil end
    if type(isrbxactive)=="function" and not isrbxactive() then return nil end
    pasting=true
    local before=TextBox.Text
    TextBox.TextTransparency=1
    TextBox.Text=""
    TextBox:CaptureFocus()
    task.wait(0.05)
    keypress(0x11);keypress(0x56) -- Ctrl+V
    task.wait(0.03)
    keyrelease(0x56);keyrelease(0x11)
    local started=os.clock()
    while TextBox.Text=="" and os.clock()-started<0.4 do task.wait() end
    local got=TextBox.Text
    TextBox:ReleaseFocus()
    TextBox.Text=before
    TextBox.TextTransparency=0
    pasting=false
    return got
end
local function GetClipboardText()
    if type(ReadClipboard)=="function" then
        local ok,text=pcall(ReadClipboard)
        if ok and type(text)=="string" then return text end
    end
    return NativePaste()
end
CopyButton.Activated:Connect(function()
    if pasting or isCheckingKey or verified then return end
    local raw=GetClipboardText()
    if raw==nil then
        -- no way to read it for them: put the cursor in the field instead
        TextBox:CaptureFocus()
        Notify(isPhone and "Hold the key field and tap Paste." or "Press Ctrl+V to paste your key.",White)
        return
    end
    local text=(raw:gsub("%s",""))
    if text=="" then
        FlashField(Orange)
        Notify("⚠️ Clipboard is empty. Copy your key first.",Orange)
        return
    end
    TextBox.Text=text
    if LooksLikeKey(text) then
        PlayPasted()
        Notify("Key pasted! Press Verify Key to continue.",CopyGreen)
    else
        FlashField(Orange)
        Notify("⚠️ Enter an AJJANS key or a 32-character Luarmor key.",Orange)
    end
end)
-- Auto-detect: when the window opens, and whenever the player comes back to Roblox (e.g. from the
-- key site), an empty field picks up a key sitting on the clipboard. Anything else is left alone.
local function DetectClipboardKey()
    if pasting or isCheckingKey or verified or not ScreenGui.Parent or TextBox.Text~="" then return end
    local raw=GetClipboardText()
    local text=raw and (raw:gsub("%s","")) or ""
    if LooksLikeKey(text) and TextBox.Text=="" and not isCheckingKey then
        TextBox.Text=text
        PlayPasted()
        Notify("Key detected from clipboard! Press Verify Key to continue.",CopyGreen)
    end
end
local FocusConnection=UserInputService.WindowFocused:Connect(function() task.delay(0.3,DetectClipboardKey) end)
ScreenGui.Destroying:Connect(function() FocusConnection:Disconnect() end)
task.delay(0.9,DetectClipboardKey)
TextBox:GetPropertyChangedSignal("Text"):Connect(function()
    local length=#(TextBox.Text:gsub("%s",""))
    KeyCounter.Text=length.."/32"
    Animate(KeyCounter,0.2,{TextColor3=length==32 and Green or length>32 and Orange or Color3.fromRGB(120,116,118)})
    if length==32 and not isCheckingKey then VerifySweep() end
end)
TextBox.Focused:Connect(function()
    Animate(InputStroke,0.2,{Transparency=0.2})
    local maxScroll=math.max(0,Scroll.CanvasSize.Y.Offset-Scroll.AbsoluteSize.Y)
    Scroll.CanvasPosition=Vector2.new(0,math.clamp(440*MainFrame.AbsoluteSize.X/ART_W,0,maxScroll))
end)
TextBox.FocusLost:Connect(function() Animate(InputStroke,0.25,{Transparency=1}) end)
-- Drag the window by its header on desktop.
local dragInput,dragStart,startPos=nil,nil,nil
DragHandle.InputBegan:Connect(function(input)
    if isPhone then return end
    if input.UserInputType==Enum.UserInputType.MouseButton1 or input.UserInputType==Enum.UserInputType.Touch then
        dragInput,dragStart,startPos=input,input.Position,Scroll.Position
        input.Changed:Connect(function()
            if input.UserInputState==Enum.UserInputState.End and dragInput==input then dragInput=nil end
        end)
    end
end)
local DragConnection=UserInputService.InputChanged:Connect(function(input)
    if not dragInput then return end
    if input.UserInputType~=Enum.UserInputType.MouseMovement and input~=dragInput then return end
    local delta=input.Position-dragStart
    local area,size=Root.AbsoluteSize,Scroll.AbsoluteSize
    local maxX,maxY=math.max(0,(area.X-size.X)/2),math.max(0,(area.Y-size.Y)/2)
    Scroll.Position=UDim2.new(0.5,math.clamp(startPos.X.Offset+delta.X,-maxX,maxX),0.5,math.clamp(startPos.Y.Offset+delta.Y,-maxY,maxY))
end)
ScreenGui.Destroying:Connect(function() DragConnection:Disconnect() end)
-- Ambient motion: breathing title glow, pulsing OR badge and an occasional shine on the main buttons.
Loop(Title,1.8,{TextStrokeTransparency=0.55})
task.delay(1,function() if OrText.Parent then Loop(OrText,1.2,{TextTransparency=0.35}) end end)
task.spawn(function()
    task.wait(1.2)
    while ScreenGui.Parent do
        if not isCheckingKey and not verified then VerifySweep() end
        task.wait(1.8)
        if not ScreenGui.Parent then break end
        BuySweep()
        task.wait(2.6)
    end
end)
-- Entrance: window pops in, then the content fades in from top to bottom.
local EntranceScale=New("UIScale",Scroll,{Scale=0.9})
Scroll.Position=UDim2.new(0.5,0,0.5,24)
Animate(EntranceScale,0.45,{Scale=1},Enum.EasingStyle.Back)
Animate(Scroll,0.4,{Position=UDim2.fromScale(0.5,0.5)})
for _,object in ipairs(MainFrame:GetDescendants()) do
    local delay=object:IsA("GuiObject") and math.clamp(object.AbsolutePosition.Y-MainFrame.AbsolutePosition.Y,0,math.huge)/math.max(1,MainFrame.AbsoluteSize.Y)*0.35 or 0
    if object:IsA("ImageLabel") then
        object.ImageTransparency=1
        task.delay(object==Background and 0 or delay,function() Animate(object,0.3,{ImageTransparency=0}) end)
    elseif object:IsA("TextLabel") or object:IsA("TextButton") or object:IsA("TextBox") then
        local target=object.TextTransparency
        object.TextTransparency=1
        task.delay(0.08+delay,function() Animate(object,0.3,{TextTransparency=target}) end)
    end
end

GetKeyButton.MouseButton1Click:Connect(function()
    if CopyToClipboard(Linkvertise_URL) then
        Notify("Key link copied! Paste it in your browser.", White)
    else
        Notify("Clipboard unsupported. Link: " .. Linkvertise_URL, Orange)
    end
end)

BuyPremiumButton.MouseButton1Click:Connect(function()
    local copied = CopyToClipboard(Premium_URL)
    BuyPremiumButton.Text = copied and "Store Link Copied!" or "Copy Failed"
    TweenService:Create(BuyPremiumButton, TweenInfo.new(0.2), {
        BackgroundColor3 = Red,
        TextColor3 = White
    }):Play()
    if copied then
        Notify("Premium store link copied!", Red)
    else
        Notify("Clipboard unsupported. Store: " .. Premium_URL, Orange)
    end
    task.delay(1.5, function()
        if not BuyPremiumButton.Parent then
            return
        end
        BuyPremiumButton.Text = "Buy Permanent Key"
        TweenService:Create(BuyPremiumButton, TweenInfo.new(0.5), {
            BackgroundColor3 = Dark,
            TextColor3 = BrightRed
        }):Play()
    end)
end)

local function CheckCustomKey(key)
    if isCheckingKey or verified then return end
    SetBusy(true)
    SetStatus("Checking key...", Yellow)
    local status, networkError = RequestKeyStatus(key)
    if status and status.code == "KEY_VALID" then
        local saved, saveError = SaveKey(key)
        if not saved and status.provider ~= "luarmor" then
            Notify(saveError, Red)
            SetStatus("Could not save key — retry", Red)
            SetBusy(false)
            return
        end
        SetStatus("Verified — fetching hub...", Green)
        local runner, loadError = FetchHub()
        if not runner then
            Notify("Could not load hub: " .. tostring(loadError), Red)
            SetStatus("Loading failed — retry", Red)
            SetBusy(false)
            return
        end
        verified = true
        SetGlobalKey(key, status.provider)
        if not saved then Notify("Premium key verified. This executor could not save it for next time.", Orange) end
        Notify("Key verified! Loading hub...", Green)
        task.wait(0.6)
        if ScreenGui.Parent then ScreenGui:Destroy() end
        local ok, err = pcall(runner)
        if not ok then ReleaseRunLock(); warn("Ajjan Hub failed: " .. tostring(err)) end
        return
    end
    local message
    if status then
        message = StatusMessages[status.code] or tostring(status.message or status.code)
        if status.provider == "luarmor" and status.code == "KEY_EXPIRED" then message = "Your Luarmor key expired. Contact support to renew it." end
        if ClearSavedOn[status.code] then ClearSavedKey() end
    else message = "Could not verify your key: " .. tostring(networkError) end
    Notify(message, Red)
    SetStatus(status and status.code == "KEY_HWID_LOCKED" and "Device locked" or "Key not verified — retry", Red)
    SetBusy(false)
end


local function SubmitKey(raw)
    local key = CleanKey(raw)
    if key == "" then
        Notify("⚠️ Paste your key first.", Orange)
        return
    end
    if not LooksLikeKey(key) then
        Notify("⚠️ Enter an AJJANS key or your 32-character Luarmor key.", Orange)
        return
    end
    TextBox.Text = key
    task.spawn(CheckCustomKey, key)
end

CheckButton.MouseButton1Click:Connect(function()
    SubmitKey(TextBox.Text)
end)

TextBox.FocusLost:Connect(function(enterPressed)
    if enterPressed then
        SubmitKey(TextBox.Text)
    end
end)

local savedKey = ReadSavedKey()
if savedKey then
    TextBox.Text = savedKey
    SetStatus("Checking saved key...", Yellow)
    task.spawn(CheckCustomKey, savedKey)
else
    SetStatus("Enter your key to verify", Red)
end
