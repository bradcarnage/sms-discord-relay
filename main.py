import discord
from discord import TextChannel, Thread, utils
from discord.ext import commands
from datetime import datetime, timezone, timedelta
import asyncio, urllib, base64, json, time, re
# import GSMEncoding
from urllib.parse import urlencode
from urllib.request import Request, urlopen
bot = commands.Bot(command_prefix="!",intents=discord.Intents.all()) #intents are required depending on what you wanna do with your bot

class MessageParser(object):
    """AI CONVERSION FROM JAVASCRIPT TO PYTHON (STOLEN FROM WEBUI)
    these functions do some weird shit with encoding and decoding text messages.
    i'm not one to fuck with it, thank you very much, original developers."""
    def __init__(self):
        super(MessageParser, self).__init__()
        self.GSM7_Table = ["000A", "000C", "000D", "0020", "0021", "0022", "0023", "0024", "0025", "0026", "0027", "0028", "0029", "002A", "002B", "002C", "002D", "002E", "002F", "0030", "0031", "0032", "0033", "0034", "0035", "0036", "0037", "0038", "0039", "003A", "003A", "003B", "003C", "003D", "003E", "003F", "0040", "0041", "0042", "0043", "0044", "0045", "0046", "0047", "0048", "0049", "004A", "004B", "004C", "004D", "004E", "004F", "0050", "0051", "0052", "0053", "0054", "0055", "0056", "0057", "0058", "0059", "005A", "005B", "005C", "005D", "005E", "005F", "0061", "0062", "0063", "0064", "0065", "0066", "0067", "0068", "0069", "006A", "006B", "006C", "006D", "006E", "006F", "0070", "0071", "0072", "0073", "0074", "0075", "0076", "0077", "0078", "0079", "007A", "007B", "007C", "007D", "007E", "00A0", "00A1", "00A3", "00A4", "00A5", "00A7", "00BF", "00C4", "00C5", "00C6", "00C7", "00C9", "00D1", "00D6", "00D8", "00DC", "00DF", "00E0", "00E4", "00E5", "00E6", "00E8", "00E9", "00EC", "00F1", "00F2", "00F6", "00F8", "00F9", "00FC", "0393", "0394", "0398", "039B", "039E", "03A0", "03A3", "03A6", "03A8", "03A9", "20AC"]
        self.GSM7_Table_Extend = ["007B", "007D", "005B", "005D", "007E", "005C", "005E", "20AC", "007C"]
        self.specialChars = ["000D", "000A", "0009", "0000"]
        self.specialCharsIgnoreWrap = ["0009", "0000"]
        
    def getEncodeType(self, d):
        b = "GSM7_default"
        e = 0
        if not d:
            return {
                'encodeType': b,
                'extendLen': e
            }
        for c in d:
            a = format(ord(c), '04X')
            if a in self.GSM7_Table_Extend:
                e += 1
            if a not in self.GSM7_Table:
                b = "UNICODE"
                e = 0
                break
        return {
            'encodeType': b,
            'extendLen': e
        }
    def encodeMessage(self, e):
        # delete all non-ascii characters, because we don't know what those are lol
        e = re.sub(r'[^\x00-\x7F]', '', e)
        # e = e.encode('ascii',errors='ignore')
        d = 0
        c = ""
        if not e:
            return c
        for f in e:
            a = ord(f)
            if d != 0:
                if 56320 <= a and a <= 57343:
                    c += format(65536 + ((d - 55296) << 10) + (a - 56320), '04X')
                    d = 0
                    continue
                else:
                    d = 0
            if 55296 <= a and a <= 56319:
                d = a
            else:
                cp = format(a, '04X')
                c += cp
        return c
    def decodeMessage(self, c):
        if not c:
            return ""
        a = self.specialCharsIgnoreWrap
        return ''.join([chr(int(e, 16)) if e not in a else "" for e in re.findall('([A-Fa-f0-9]{1,4})', c)]).encode('utf-16', 'surrogatepass').decode('utf-16')
    def dec2hex(a):
        return format(a, '04X')
    def hex2char(b):
        a = ""
        c = int(b, 16)
        if c <= 65535:
            a += chr(c)
        else:
            if c <= 1114111:
                c -= 65536
                a += chr(55296 | (c >> 10)) + chr(56320 | (c & 1023))
        return a

    def base64_enc(self, content):
        return(base64.b64encode(content.encode()).decode())

    # # 23;09;29;10;48;54;-7
    # def decode_datetime_with_offset(self, formatted_datetime_with_offset):
    #     # Split the string into date/time components and UTC offset
    #     formatted_datetime_with_offset = re.sub(",", ";", formatted_datetime_with_offset)
    #     components = formatted_datetime_with_offset.split(';')
    #     print(f'test1 {components[:-1]} {components[-1]}')
    #     date_time_str = ';'.join(components[:-1])
    #     utc_offset = int(components[-1])%24
    #     # Parse the date/time components
    #     date_time = datetime.strptime(date_time_str, "%y;%m;%d;%H;%M;%S")
    #     # Apply the UTC offset
    #     date_time = date_time.replace(tzinfo=timezone(timedelta(hours=utc_offset)))
    #     return date_time

    # 23;09;29;10;48;54;-7
    def encode_datetime_with_offset(self, current_datetime=None):
        if current_datetime == None:
            localzone = datetime.now(timezone.utc).astimezone().tzinfo
            current_datetime = datetime.now(localzone)
        # Get current date and time in UTC
        # current_datetime = datetime.now(timezone.utc)
        # Format date and time components
        formatted_datetime = current_datetime.strftime("%y;%m;%d;%H;%M;%S")

        # Calculate UTC offset
        utc_offset = current_datetime.utcoffset().total_seconds() // 3600

        # Combine formatted date and time with UTC offset
        formatted_datetime_with_offset = f"{formatted_datetime};{int(utc_offset):02d}"
        return formatted_datetime_with_offset
mp = MessageParser()

class RouterConnection(object):
    """docstring for RouterConnection"""
    def __init__(self, routerip, adminpw):
        global mp
        super(RouterConnection, self).__init__()
        self.routerip = routerip
        self.adminpw = adminpw
        self.defaultcountrycode = "+1"
        
    async def send_sms(self, number, message):
        message = message.strip()
        number = re.sub("[^0-9^.]", "", number).lstrip(self.defaultcountrycode)
        print(f"Sending message to {number}: \n{message}")
        resp = await self.post_to_router({'goformId': 'SEND_SMS', 'notCallback': 'true', 'Number': number, 'sms_time': mp.encode_datetime_with_offset(), 'MessageBody': mp.encodeMessage(message), 'ID': -1, 'encode_type': 'GSM7_default'})
        result = resp['result']
        if result == 'failure':
            await self.set_login()
            resp = await self.post_to_router({'goformId': 'SEND_SMS', 'notCallback': 'true', 'Number': number, 'sms_time': mp.encode_datetime_with_offset(), 'MessageBody': mp.encodeMessage(message), 'ID': -1, 'encode_type': 'GSM7_default'})
            result = resp['result']
        print(f'msg send result: {result}')
        return result

    async def set_login(self):
        # print('Logging back in!')
        result = await self.post_to_router({'goformId': 'LOGIN', 'password': mp.base64_enc(self.adminpw)})
        result = result['result']
        print(f'Login result: {result}')
        if result == 'failure':
            print(f'Something went wrong; Login result {result}')

    async def delete_messages(self, message_ids):
        if len(message_ids) > 0:
            delstring = ''
            for msg_id in message_ids:
                delstring = f'{delstring}{msg_id};'
            result = await self.post_to_router({'goformId': 'DELETE_SMS', 'msg_id': delstring, 'notCallback': 'true'})
            if result['result'] != "success":
                await self.set_login()
                result = await self.post_to_router({'goformId': 'DELETE_SMS', 'msg_id': delstring, 'notCallback': 'true'})
            return result['result']
            # return "success"
        else:
            return None

    async def fetch_new_sms(self):
        result = await self.get_from_router({'cmd': 'sms_data_total', 'page': 0, 'data_per_page': 500, 'mem_store': 1, 'tags':10, 'order_by': 'order+by+id+desc', '_': int(time.time())})
        if 'sms_data_total' in result:
            # we must re-login
            await self.set_login()
            result = await self.get_from_router({'cmd': 'sms_data_total', 'page': 0, 'data_per_page': 500, 'mem_store': 1, 'tags':10, 'order_by': 'order+by+id+desc', '_': int(time.time())})
        # print(f'fetch_new_sms: {result}')
        # tag = 1 : outgoing
        # tag = 2 : incoming
        del_msgs = []
        returndata = []
        if 'messages' in result and len(result['messages']) > 0:
            for entry in reversed(result['messages']):
                print('itermessage')
                try:
                    entry['content'] = mp.decodeMessage(entry['content']).strip()
                except Exception as e:
                    print(e)
                    print(entry['content'])
                    # entry['content'] = f"{entry['content']}\n{str(e)}".strip()
                    entry['content'] = str(e)
                    pass
                print('content_checked')
                # try:
                #     entry['date'] = mp.decode_datetime_with_offset(entry['date'])
                # except Exception as e:
                #     entry['date'] = f"{entry['date']}\n{str(e)}".strip()
                #     pass
                # remove default country code
                entry['number'] = entry['number'].lstrip(self.defaultcountrycode)
                entry['tag'] = int(entry['tag'])
                returndata.append(entry)
                del_msgs.append(entry['id'])
            await self.delete_messages(del_msgs)
        print(f'returndata: {returndata}')
        return returndata

    async def get_from_router(self, params):
        url_params = {'istest': 'false'}
        url_params.update(params)
        url = f'http://{self.routerip}/reqproc/proc_get' # Set destination URL here  
        query_string = urllib.parse.urlencode(url_params)
        url = url + "?" + query_string
        with urllib.request.urlopen(url) as response: 
            response_text = response.read().decode('utf8')
            # print(f'response_text: {response_text}')
            return(json.loads(response_text))

    async def post_to_router(self, params):
        url_params = {'istest': 'false'}
        url_params.update(params)
        url = f'http://{self.routerip}/reqproc/proc_post' # Set destination URL here
        request = Request(url, urlencode(url_params).encode())
        # print(urlencode(url_params))
        return(json.loads(urlopen(request).read().decode()))

async def send_sms_to_thread(thread_name, message):
    global sms_channel_id, sms_role_name
    try:
        channel = bot.get_channel(sms_channel_id)
        if isinstance(channel, TextChannel):
            target_thread = next((t for t in channel.threads if isinstance(t, Thread) and t.name == thread_name), None)
            if target_thread is None:
                target_thread = await channel.create_thread(name=thread_name)
                try:
                    role = utils.get(channel.guild.roles, name=sms_role_name)
                    await target_thread.send(f"Start of thread - <@&{role.id}>")
                except Exception as e:
                    print(f"{e}")
                    pass
            result = await target_thread.send(message)
            return result
    except Exception as e:
        print(f"{e}")
        pass


async def check_perms(ctx):
    global sms_role_name
    user = None
    try:
        user = ctx.author
    except Exception as e:
        user = ctx.user
        pass
    role = utils.get(ctx.guild.roles, name=sms_role_name)
    if role in user.roles:
        return True;
    else:
        return False;

@bot.tree.command(name="sendmsg", description="<number> <message> - Send an SMS")
async def sendmsg(ctx: discord.Interaction, number: str, message: str):
    try:
        if await check_perms(ctx):
            message = message.strip()
            number = re.sub("[^0-9^.]", "", number)
            result = await rc.send_sms(number, message)
            print(f'Send message command result {result}')
            if result == 'success':
                response = await ctx.response.send_message(f"message sent; check #\"{number}\"", ephemeral=True)
            else:
                await ctx.response.send_message(f"message could not be sent.", ephemeral=True)
            # print(result)
        else:
            await ctx.response.send_message(f"You do not have permission to run this command", ephemeral=True)
    except Exception as e:
        await ctx.response.send_message(f"{e}", ephemeral=True)
        pass


@bot.event  
async def on_message(ctx):
    if ctx.author.bot:
        return
    global sms_channel_id
    if isinstance(ctx.channel, discord.Thread) and ctx.channel.parent_id == sms_channel_id:
        if await check_perms(ctx):
            await rc.send_sms(ctx.channel.name, ctx.content)
        await ctx.delete()

@bot.event
async def on_ready():
    # await bot.sync() #sync the command tree
    await bot.tree.sync()
    print("Bot is ready and online")
    # await send_to_thread(bot.get_channel(1157376879511224430), "5599160001", "test message")
    # await rc.send_sms('5599160001', 'test1234')
    while True:
        messages = await rc.fetch_new_sms()
        for message in messages:
            # message['number'] # phone no of other party
            # message['content'] # converted message, or raw content with error msg
            # message['tag'] # in or out (1 or 2)
            # message['id'] # refrence ID since device reset
            content = message['content']
            print(f"messagetag: {message['tag']}")
            print(f"messagecontent: {content}")
            if message['tag'] == 1:
                # log incoming message, escaping any formatting that denotates outgoing
                try:
                    content = re.sub('^> |\n> ', '\\> ', content)
                except Exception as e:
                    print(f"{e}")
                    pass
            else:
                # log outgoing message
                content = '> '+content

            print(f"New message: {message['number']} {content}")
            await send_sms_to_thread(message['number'], content)
        await asyncio.sleep(1)
rc = RouterConnection('192.168.0.1', 'admin')
sms_channel_id = 000000000000000000
sms_role_name = "SMS Bot"

async def main():
    await bot.start("0000000000000000000000000000000000000000000000000000000000")

asyncio.run(main())

