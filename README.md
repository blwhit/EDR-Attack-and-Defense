# EDR Home Lab: Attack and Defense

## Project: 
This lab is dedicated to simulating a real cyber attack and endpoint detection and response. Utilizing Eric Capuano's guide online, I will be using virtual machines to simulate the threat & victim machines. The attack machine will utilize 'Sliver' as a C2 framework to attack a Windows endpoint machine, which will be running 'LimaCharlie' as an EDR solution.

Eric Capuano's Guide: https://blog.ecapuano.com/p/so-you-want-to-be-a-soc-analyst-intro?utm_campaign=post&utm_medium=web 

#


## Setup
The first step to the lab is setting up both machines. The attack machine will run on Ubuntu Server, and the endpoint will be running Windows 11. In order for this lab to work smoothly Microsoft Defender should be turned off (along with other settings). I am also going to be installing Sliver on the Ubuntu machine as my primary attack tool, and setting up LimaCharlie on the Windows machine as an EDR solution. LimaCharlie will have a sensor linked to the windows machine, and will be importing sysmon logs.
#

Windows 11 Machine - 
![Capture](https://github.com/blwhit/EDR-Attack-and-Defense/assets/141170960/75977c64-7faa-4b38-a5ad-1824cec2e508)
![Capture1](https://github.com/blwhit/EDR-Attack-and-Defense/assets/141170960/aebc3ac4-3631-4efe-a0f3-fc301997e48e)
![Capture4](https://github.com/blwhit/EDR-Attack-and-Defense/assets/141170960/d42cbd4d-7732-4f45-9e22-66457d2056ac)
![Capture5](https://github.com/blwhit/EDR-Attack-and-Defense/assets/141170960/ec31655e-ee37-48de-bcf0-ae04c8f5bb06)

#
Ubuntu Server Machine - 
![Capture6](https://github.com/blwhit/EDR-Attack-and-Defense/assets/141170960/1ed6cce1-4793-412b-8b8d-d0b65fbc6aa2)

#


## The Attacks, and the Defense
The first step is to generate our payload on Sliver, and implant the malware into the Windows host machine. Then we can create a command and control session after the malware is executed on the endpoint. 
#


![Capture9](https://github.com/blwhit/EDR-Attack-and-Defense/assets/141170960/10b13df6-8edd-4f79-bc04-e6fdca12cf68)
![Capture11](https://github.com/blwhit/EDR-Attack-and-Defense/assets/141170960/fd752f1f-324c-4d76-93f0-d1db0f6d5120)
![Capture12](https://github.com/blwhit/EDR-Attack-and-Defense/assets/141170960/4e4c15cd-4e6a-42ce-b554-73137e203a1c)
#


Now that we have a live session between the two machines, the attack machine can begin peeking around, checking priveleges, getting host information, and checking what type of security the host has. 

![Capture13](https://github.com/blwhit/EDR-Attack-and-Defense/assets/141170960/1daf9c90-bab4-4a0c-ac98-5322a58dbc5e)
![Capture15](https://github.com/blwhit/EDR-Attack-and-Defense/assets/141170960/0400c100-5a4b-4ab8-bc73-46f6e7e634a7)

#

On the host machine we can look inside our LimaCharlie SIEM and see telemetry from the attacker. We can identify the payload thats running and see the IP its connected to.

![Capture16](https://github.com/blwhit/EDR-Attack-and-Defense/assets/141170960/5e6c093c-91f8-4ad3-967c-ad51dcb2e9aa)
![Capture17](https://github.com/blwhit/EDR-Attack-and-Defense/assets/141170960/ae55f753-45d1-40c3-905a-3f2d0df716f5)
![Capture18](https://github.com/blwhit/EDR-Attack-and-Defense/assets/141170960/4122902c-702b-4ff6-bebf-98d1d41256d2)

#
We can also use LimaCharlie to scan the hash of the payload through VirusTotal; however, it will be clean since we just created the payload ourselves.

![Capture19](https://github.com/blwhit/EDR-Attack-and-Defense/assets/141170960/96a2a29c-08dc-40aa-a40f-09eb9d8500da)
![Capture20](https://github.com/blwhit/EDR-Attack-and-Defense/assets/141170960/f62fdcc2-458a-4929-9527-1ea97f38acb4)


#
Now on the attack machine we can simulate an attack to steal credentials by dumping the LSASS memory. In LimaCharlie we can check the sensors, observe the telemetry, and write rules to detect the sensitive process. 

![Capture22](https://github.com/blwhit/EDR-Attack-and-Defense/assets/141170960/7c420d51-63f2-43ee-9423-6eab89a00910)
![Capture23](https://github.com/blwhit/EDR-Attack-and-Defense/assets/141170960/b6ca8680-a990-4543-b4ee-55f543e68856)
![Capture24](https://github.com/blwhit/EDR-Attack-and-Defense/assets/141170960/f7c4bc72-94d9-405c-bb5d-0e10fa505f4c)


#
Now instead of simply detection, we can practice using LimaCharlie to write a rule that will detect and block the attacks coming from the Sliver server. On the Ubuntu machine we can simulate parts of a ransomware attack, by attempting to delete the volume shadow copies. In LimaCharlie we can view the telemetry and then write a rule that will block the attack entirely. After we create the rule in our SIEM, the Ubuntu machine will have no luck trying the same attack again.




![Capture26](https://github.com/blwhit/EDR-Attack-and-Defense/assets/141170960/0e95674a-5ea7-4dd3-a5d9-462f8f93b950)
![Capture27](https://github.com/blwhit/EDR-Attack-and-Defense/assets/141170960/4915d804-7a8e-471c-8d46-e78b13792dce)
![Capture29](https://github.com/blwhit/EDR-Attack-and-Defense/assets/141170960/67cfa38a-af15-46d2-9773-fbc4086eade5)
![Capture30](https://github.com/blwhit/EDR-Attack-and-Defense/assets/141170960/6c59bd6c-de0f-412c-a116-b1f8923cedef)
 
