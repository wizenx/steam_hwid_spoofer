A Steam Hardware Spoofer using hooks. C++17.

This spoofer is temp and for one steam session, if you changing account - please launch injector again because its only one session, because steam every launch collects this data (you can add monitoring but i was too lazy tbh).

Steam uses this to identify the user. The values ​​are converted to a SHA1 hash and sent to the server, which can validate and apply any sanctions. So, VACLIVE or Steam could very well use this.

There have been stories about HWID bans within Steam itself before.

VAC also collected system information before, but since VAC modules don't stream anymore, this information is used specifically.

The data is sent in the following format:
GUIDHASH + "BB3" + MACHASH + "FF2" + SERIALHASH + "3B3"

<img width="955" height="990" alt="image" src="https://github.com/user-attachments/assets/1a1ff8f0-d778-49f9-bcf4-129b07a0e450" />
<img width="1280" height="889" alt="image" src="https://github.com/user-attachments/assets/09dac613-e453-4fa4-95dc-a89bdf3632d4" />
<img width="1280" height="888" alt="image" src="https://github.com/user-attachments/assets/e3934daa-0069-48d8-8be7-970a6a796411" />
<img width="1280" height="816" alt="image" src="https://github.com/user-attachments/assets/d8371374-0bdd-4b01-82c8-02a6dde338bf" />

string: FillInMachineIDInfo() -> в steamclient64.dll (1 xref).

