#define _GNU_SOURCE
#include <sched.h>
#include <syslog.h>
#include "libUseful-5/libUseful.h"

#ifdef USE_NO_NEW_PRIVS
#include <sys/prctl.h>
#endif

#define FLAG_INTERACTIVE   1
#define FLAG_MENU          2
#define FLAG_ONESHOT     256
#define FLAG_NOSU       1024
#define FLAG_NONET      2048
#define FLAG_NOIPC      4096
#define FLAG_NOPIDS     8192
#define FLAG_NOEXEC    16384

#define VERSION "1.0"

char *RulesDir=NULL;
ListNode *Rules=NULL;
int LogLevel=LOG_CRIT;

typedef struct
{
    int Flags;
    int Nice;
    int Timeout;
    int MaxFiles;
    int MaxProcs;
    unsigned long MaxMem;
    unsigned long MaxFileSize;
    char *OTP;
    char *Challenge;
    char *Title;
    char *Cmd;
    char *Args;
    char *Banner;
    char *HostName;
    char *SHA256;
} TProcSettings;


TProcSettings GlobalSettings;
STREAM *StdIn;


void ProcSettingsDestroy(void *p_Settings)
{
    TProcSettings *Settings;

    if (! p_Settings) return;
    Settings=(TProcSettings *) p_Settings;
    Destroy(Settings->OTP);
    Destroy(Settings->Challenge);
    Destroy(Settings->Title);
    Destroy(Settings->Cmd);
    Destroy(Settings->Args);
    Destroy(Settings->Banner);
    Destroy(Settings->HostName);
    Destroy(Settings->SHA256);

    free(Settings);
}



void ProcessParseSettings(TProcSettings *Settings, const char *Config)
{
    char *Name=NULL, *Value=NULL;
    const char *ptr;
    int Flags=0;

    ptr=GetNameValuePair(Config, "\\S", "=", &Name, &Value);
    while (ptr)
    {
        if (strcmp(Name, "menu")==0) Settings->Flags |= FLAG_MENU;
        else if (strcmp(Name, "once")==0) Settings->Flags |= FLAG_ONESHOT;
        else if (strcmp(Name, "interactive")==0) Settings->Flags |= FLAG_INTERACTIVE;
        else if (strcmp(Name, "nosu")==0) Settings->Flags |= FLAG_NOSU;
        else if (strcmp(Name, "nonet")==0) Settings->Flags |= FLAG_NONET;
        else if (strcmp(Name, "noipc")==0) Settings->Flags |= FLAG_NOIPC;
        else if (strcmp(Name, "noexec")==0) Settings->Flags |= FLAG_NOEXEC;
        //else if (strcmp(Name, "nopid")==0) Settings->Flags |= FLAG_NOPIDS;
        else if (strcmp(Name, "nice")==0) Settings->Nice=atoi(Value);
        else if (strcmp(Name, "timeout")==0) Settings->Timeout=ParseDuration(Value);
        else if (strcmp(Name, "files")==0) Settings->MaxFiles=atoi(Value);
        else if (strcmp(Name, "fsize")==0) Settings->MaxFileSize=(unsigned long) FromIEC(Value, 1024);
        else if (strcmp(Name, "mem")==0) Settings->MaxMem=(unsigned long) FromIEC(Value, 1024);
        else if (strcmp(Name, "procs")==0) Settings->MaxProcs=atoi(Value);
        else if (strcmp(Name, "otp")==0) Settings->OTP=CopyStr(Settings->OTP, Value);
        else if (strcmp(Name, "totp")==0) Settings->OTP=CopyStr(Settings->OTP, Value);
        else if (strcmp(Name, "challenge")==0) Settings->Challenge=CopyStr(Settings->Challenge, Value);
        else if (strcmp(Name, "title")==0) Settings->Title=CopyStr(Settings->Title, Value);
        else if (strcmp(Name, "cmd")==0) Settings->Cmd=CopyStr(Settings->Cmd, Value);
        else if (strcmp(Name, "args")==0) Settings->Args=CopyStr(Settings->Args, Value);
        else if (strcmp(Name, "banner")==0) Settings->Banner=CopyStr(Settings->Banner, Value);
        else if (strcmp(Name, "hostname")==0) Settings->HostName=CopyStr(Settings->HostName, Value);
        else if (strcmp(Name, "sha256")==0) Settings->SHA256=CopyStr(Settings->SHA256, Value);

        ptr=GetNameValuePair(ptr, "\\S", "=", &Name, &Value);
    }


    Destroy(Name);
    Destroy(Value);
}


TProcSettings *ProcessSettingsNew(const char *Config)
{
    TProcSettings *Settings;

    Settings=(TProcSettings *) calloc(1, sizeof(TProcSettings));
    Settings->Flags=GlobalSettings.Flags;
    Settings->Timeout=GlobalSettings.Timeout;
    Settings->Nice=GlobalSettings.Nice;
    Settings->MaxFiles=GlobalSettings.MaxFiles;
    Settings->MaxFileSize=GlobalSettings.MaxFileSize;
    Settings->MaxMem=GlobalSettings.MaxMem;
    Settings->MaxProcs=GlobalSettings.MaxProcs;
    Settings->HostName=CopyStr(Settings->HostName, GlobalSettings.HostName);
    ProcessParseSettings(Settings, Config);

    return(Settings);
}


void LogMessage(const char *Event, const char *Message)
{
    const char *ptr;

    ptr=getenv("SSH_CLIENT");
    if (StrValid(ptr)) syslog(LogLevel, "%s from ssh{%s}: %s", Event, ptr, Message);
    else syslog(LogLevel, "%s: %s", Event, Message);
}


int ConfigFileValid(const char *Tempstr)
{
    struct stat FStat;

    stat(Tempstr, &FStat);

//do not read any file owned by the current user
    if (FStat.st_uid == getuid())
    {
        syslog(LOG_CRIT, "config file for user '%s' owned by that user, aborting.", LookupUserName(FStat.st_uid));
        return(FALSE);
    }

//do not read any file owned by the current user
    if (FStat.st_mode & (S_IXGRP | S_IXOTH))
    {
        syslog(LOG_CRIT, "config file for user '%s' is group or world writable, aborting.", LookupUserName(FStat.st_uid));
        return(FALSE);
    }

    return(TRUE);
}



void LoadConfigAddRule(const char *Rule)
{
    char *Path=NULL;
    const char *ptr;
    TProcSettings *Settings;

    ptr=GetToken(Rule, "\\S", &Path, GETTOKEN_QUOTES);
    Settings=ProcessSettingsNew(ptr);
    if (StrValid(Settings->Args)) Path=MCatStr(Path, " ", Settings->Args);
    ListAddNamedItem(Rules, Path, CopyStr(NULL, Rule));

    ProcSettingsDestroy(Settings);
    Destroy(Path);
}


int LoadConfig()
{
    char *Tempstr=NULL;
    int RetVal=FALSE;
    ListNode *Node;
    STREAM *S;

    if (! Rules) Rules=ListCreate();

    Tempstr=MCopyStr(Tempstr, RulesDir, LookupUserName(getuid()), ".conf", NULL);
    if (ConfigFileValid(Tempstr))
    {
        S=STREAMOpen(Tempstr, "r");
        if (S)
        {
            Tempstr=STREAMReadLine(Tempstr, S);
            while (Tempstr)
            {
                StripTrailingWhitespace(Tempstr);
                StripLeadingWhitespace(Tempstr);
                if (*Tempstr=='#') /* comment. do nothing. */ ;
                else LoadConfigAddRule(Tempstr);
                Tempstr=STREAMReadLine(Tempstr, S);
            }
            RetVal=TRUE;
            STREAMClose(S);
        }

        Node=ListFindNamedItem(Rules, "narrowsh");
        if (Node) ProcessParseSettings(&GlobalSettings, (const char *) Node->Item);
    }

    Destroy(Tempstr);

    return(RetVal);
}


void PrintVersion()
{
    printf("narrowsh: %s\n\n", VERSION);
    exit(0);
}


void PrintHelp()
{
    printf("usage:\n");
    printf("    narrowsh <options> -c <command line>\n");
    printf("    narrowsh <options> -i\n");
    printf("    narrowsh <options>\n");
    printf("\nwithout any arguments narrowsh tries to open /etc/narrowsh/<username>.conf and read settings from that\n\n");
    printf("options:\n");
    printf("  -c <command line>  command-line to run, as in ´/bin/sh -c <command>´\n");
    printf("  -i                 force interactive mode (otherwise must be set in config file>\n");
    printf("  -m                 force menu mode (otherwise must be set in config file>\n");
		printf("  -1                 'oneshot' menu, only allow running one program, then disconnect after it's run\n");
		printf("  -once              'oneshot' menu, only allow running one program, then disconnect after it's run\n");
		printf("  -oneshot           'oneshot' menu, only allow running one program, then disconnect after it's run\n");
    printf("  -S                 disallow use of su/sudo/suid\n");
    printf("  -X                 disallow running further child programs (attempts to block 'fork()')\n");
    printf("  -N                 enter a namespace with no network access\n");
    printf("  -I                 enter a namespace with no Inter Process Communication access\n");
    //printf("  -P               enter a namespace that cannot see other processes running on the system\n");
    printf("  -n <value>         run with process priority (´nice´) of <value>\n");
    printf("  -T <value>         inactivity timeout after ´value´ secs. Suffixes of ´m´ ´h´ can be used for minutes and hours\n");
    printf("  -f <value>         maximum numbers of files that can be opened\n");
    printf("  -files <value>     maximum numbers of files that can be opened\n");
    printf("  -maxfiles <value>  maximum numbers of files that can be opened\n");
    printf("  -F <value>         max file size bytes. Supports suffixes ´k´, ´M´ and ´G´ for kilo, mega and giga\n");
    printf("  -fsize <value>     max file size bytes. Supports suffixes ´k´, ´M´ and ´G´ for kilo, mega and giga\n");
    printf("  -M <value>         max memory use in bytes. Supports suffixes ´k´, ´M´ and ´G´ for kilo, mega and giga\n");
    printf("  -mem <value>       max memory use in bytes. Supports suffixes ´k´, ´M´ and ´G´ for kilo, mega and giga\n");
    printf("  -?                 print this help\n");
    printf("  -help              print this help\n");
    printf("  --help             print this help\n");

    printf("\nconfig file:\n");
    printf("  Entries in config file are a single line consisting of a command-name followed by options that are either a single word, or a name=value pair. The command-name 'narrowsh' is a special case that relates to global options for the 'top' narrowsh process.\n");
    printf("\nconfig file options:\n");
    printf("  interactive        read commands from std-in like a normal shell (can only be set against 'narrowsh')\n");
    printf("  menu               display a menu of commands to choose from (can only be set against 'narrowsh')\n");
    printf("  once               only allow picking one option from the menu, and exit once that command is run\n");
		printf("  banner=<string>    set a banner to display at top of menu (can only be set against 'narrowsh')\n");
    printf("  nosu               prevent any user change via su/sudo/suid\n");
    printf("  nonet              use namespaces to disable network access\n");
    printf("  noipc              use namespaces to disable IPC access\n");
    printf("  hostname=<string>  use namespaces to 'fake' system hostname\n");
    printf("  noexec             prevent the launched process from itself spawning further execuatables (currently works by blocking fork)\n");
    //printf("  nopid              use namespaces to disable viewing other processes\n");
    printf("  nice=<value>       set processor usage level ('nice') to <value>\n");
    printf("  timeout=<value>    disconnect if idle for 'value' seconds\n");
    printf("  files=<value>      maximum number of open files\n");
    printf("  fsize=<value>      maximum file size (value can include a k,M,G suffix for kilo, mega, giga)\n");
    printf("  mem=<value>        maximum memory usage (value can include a k,M,G suffix for kilo, mega, giga)\n");
    printf("  procs=<value>      maximum number of processes for this user\n");
    printf("  otp=<key>          google-authenticator-compatible authentication using 'key'\n");
    printf("  totp=<key>         google-authenticator-compatible authentication using 'key'\n");
    printf("  challenge=<key>    challenge-response authentication using key/password 'key'\n");
    printf("  title=<string>     title of process to display in ps listings\n");
    printf("  cmd=<string>       real command-line to run\n");
    printf("  args=<string>      force command-line arguments for command\n");
    printf("  sha256=<string>    sha256 of command executable or script, command will not be run if this doesn't match\n");
    printf("\n");
		printf("If the 'args' option is used, then the user must enter a command-line that matches exactly. If it is not used, and there is a matching command that doesn't have the 'args' option, then the user will be able to provide their own arguments to the command.\n");
    printf("\nexample config file: \n");
    printf("    narrowsh interactive nopid files=20 mem=10M\n");
    printf("    /usr/sbin/ppp\n");
    printf("    /usr/bin/vi nosu nonet noipc otp=XF943Z2140XPJMMRQ6V99\n");
    printf("\nThe above config sets global rules that all applications cannot see other apps vi proc or ps, and can have a maxiumum of 20 files open and use up to 10 meg of ram. The 'interactive' keyword specifies that narrowsh will allow commands to be typed in, as well as entered using '-c'. The applications 'ppp' and 'vi' can be run. 'vi' has extra restrictions of 'no switching of user' and 'no network or ipc visiblity' and on attempting the run the 'vi' the user will be asked to authenticate using google-authenticator style OTP.\n");
    exit(0);

}




char *ParseCommandLine(char *RetStr, int argc, char **argv)
{
    CMDLINE *Cmd;
    const char *p_Arg=NULL;
    char *Tempstr=NULL;

    Cmd=CommandLineParserCreate(argc, argv);
    p_Arg=CommandLineNext(Cmd);
    while (p_Arg)
    {
        if (strcmp(p_Arg, "-c")==0) Tempstr=CopyStr(Tempstr, CommandLineNext(Cmd));
        else if (strcmp(p_Arg, "-i")==0) GlobalSettings.Flags |= FLAG_INTERACTIVE;
        else if (strcmp(p_Arg, "-m")==0) GlobalSettings.Flags |= FLAG_MENU;
        else if (strcmp(p_Arg, "-1")==0) GlobalSettings.Flags |= FLAG_ONESHOT;
        else if (strcmp(p_Arg, "-once")==0) GlobalSettings.Flags |= FLAG_ONESHOT;
        else if (strcmp(p_Arg, "-oneshot")==0) GlobalSettings.Flags |= FLAG_ONESHOT;
        else if (strcmp(p_Arg, "-S")==0) GlobalSettings.Flags |= FLAG_NOSU;
        else if (strcmp(p_Arg, "-N")==0) GlobalSettings.Flags |= FLAG_NONET;
        else if (strcmp(p_Arg, "-I")==0) GlobalSettings.Flags |= FLAG_NOIPC;
        else if (strcmp(p_Arg, "-X")==0) GlobalSettings.Flags |= FLAG_NOEXEC;
        //else if (strcmp(p_Arg, "-P")==0) GlobalSettings.Flags |= FLAG_NOPIDS;
        else if (strcmp(p_Arg, "-n")==0) GlobalSettings.Nice=atoi(CommandLineNext(Cmd));
        else if (strcmp(p_Arg, "-T")==0) GlobalSettings.Timeout=ParseDuration(CommandLineNext(Cmd));
        else if (strcmp(p_Arg, "-f")==0) GlobalSettings.MaxFiles=atoi(CommandLineNext(Cmd));
        else if (strcmp(p_Arg, "-files")==0) GlobalSettings.MaxFiles=atoi(CommandLineNext(Cmd));
        else if (strcmp(p_Arg, "-maxfiles")==0) GlobalSettings.MaxFiles=atoi(CommandLineNext(Cmd));
        else if (strcmp(p_Arg, "-F")==0) GlobalSettings.MaxFileSize=(unsigned long) FromIEC(CommandLineNext(Cmd), 1024);
        else if (strcmp(p_Arg, "-fsize")==0) GlobalSettings.MaxFileSize=(unsigned long) FromIEC(CommandLineNext(Cmd), 1024);
        else if (strcmp(p_Arg, "-M")==0) GlobalSettings.MaxMem=(unsigned long) FromIEC(CommandLineNext(Cmd), 1024);
        else if (strcmp(p_Arg, "-mem")==0) GlobalSettings.MaxMem=(unsigned long) FromIEC(CommandLineNext(Cmd), 1024);
        else if (strcmp(p_Arg, "-?")==0) PrintHelp();
        else if (strcmp(p_Arg, "-help")==0) PrintHelp();
        else if (strcmp(p_Arg, "--help")==0) PrintHelp();
        else if (strcmp(p_Arg, "--version")==0) PrintVersion();
        else Tempstr=MCatStr(Tempstr, "'", p_Arg, "' ", NULL);

        p_Arg=CommandLineNext(Cmd);
    }

    if (StrValid(Tempstr))
    {
        RetStr=MakeShellSafeString(RetStr, Tempstr, SHELLSAFE_BLANK);
        if (strcmp(RetStr, Tempstr) !=0) LogMessage("shell unsafe command line", Tempstr);
    }

    Destroy(Tempstr);

    return(RetStr);
}


int CommandMatches(const char *Cmd, const char *Allowed)
{
    const char *ptr, *match;

    //does the whole string match? Requestor supplied full path
    if (strcmp(Cmd, Allowed)==0)  return(TRUE);

    //from here on in assume requestor supplied only program name, not full path

    //get basename, but include arguments
    match=Allowed;
    for (ptr=Allowed; (*ptr != '\0') && (! isspace(*ptr)); ptr++)
    {
        if (*ptr=='/') match=ptr+1;
    }

    if (strcmp(Cmd, match)==0)  return(TRUE);


    return(FALSE);
}




ListNode *CommandFindMatch(const char *Request)
{
    ListNode *Curr;

    Curr=ListGetNext(Rules);
    while (Curr)
    {
        if (CommandMatches(Request, (const char *) Curr->Tag)) return(Curr);
        Curr=ListGetNext(Curr);
    }


    return(NULL);
}


ListNode *RequestFindMatch(const char *Request)
{
    ListNode *Item=NULL;
    char *Cmd=NULL;

//first try to find a command that matches full, with arguments
    Item=CommandFindMatch(Request);
    if (! Item)
    {
        GetToken(Request, "\\S", &Cmd, 0);
        Item=CommandFindMatch(Cmd);
    }

    Destroy(Cmd);
    return(Item);
}

int ProcessSetupRestrictions(TProcSettings *Settings)
{
    int Unshares=0;
    char *ProcessConfig=NULL, *Tempstr=NULL;
    pid_t pid;

    //all this containers stuff will eventually be handled in libUseful,
    //but that is still a work in progress
    if (Settings->Flags & FLAG_NONET) Unshares |= CLONE_NEWNET;
    if (Settings->Flags & FLAG_NOIPC) Unshares |= CLONE_NEWIPC;
    if (StrValid(Settings->HostName)) Unshares |= CLONE_NEWUTS;
    //if (Settings->Flags & FLAG_NOPIDS) Unshares |= CLONE_NEWPID;

    if (Unshares)
    {
        unshare(CLONE_NEWUSER | Unshares);
    }

    if (StrValid(Settings->HostName)) sethostname(Settings->HostName, StrLen(Settings->HostName));

    if (Settings->Nice > 0)
    {
        Tempstr=FormatStr(Tempstr, "nice=%d ", Settings->Nice);
        ProcessConfig=CatStr(ProcessConfig, Tempstr);
    }

    if (Settings->MaxMem > 0)
    {
        Tempstr=FormatStr(Tempstr, "mem=%llu ", Settings->MaxMem);
        ProcessConfig=CatStr(ProcessConfig, Tempstr);
    }

    if (Settings->MaxFiles > 0)
    {
        Tempstr=FormatStr(Tempstr, "files=%d ", Settings->MaxFiles);
        ProcessConfig=CatStr(ProcessConfig, Tempstr);
    }


    if (Settings->MaxFileSize > 0)
    {
        Tempstr=FormatStr(Tempstr, "fsize=%d ", Settings->MaxFileSize);
        ProcessConfig=CatStr(ProcessConfig, Tempstr);
    }


    if (Settings->MaxProcs > 0)
    {
        Tempstr=FormatStr(Tempstr, "nproc=%d ", Settings->Nice);
        ProcessConfig=CatStr(ProcessConfig, Tempstr);
    }


    if (Settings->HostName > 0)
    {
        Tempstr=FormatStr(Tempstr, "hostname=%s ", Settings->HostName);
        ProcessConfig=CatStr(ProcessConfig, Tempstr);
    }


    if (Settings->Flags & FLAG_NOEXEC)
    {
        ProcessConfig=CatStr(ProcessConfig, "nproc=1 ");
    }

    if (StrValid(ProcessConfig)) ProcessApplyConfig(ProcessConfig);

    if (Settings->Flags & FLAG_NOSU)
    {
#ifdef PR_SET_NO_NEW_PRIVS
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) !=0)
        {
            perror("'nosu' requested, but PR_SET_NO_NEW_PRIVS failed:");
            syslog(LOG_CRIT, "'nosu' requested, but PR_SET_NO_NEW_PRIVS failed: %s", strerror(errno));
            exit(1);
        }
#endif
    }


    Destroy(ProcessConfig);
    Destroy(Tempstr);
}


int OTPCheck(const char *Secret, const char *Response)
{
    char *Prev=NULL, *Curr=NULL, *Next=NULL;
    int RetVal=FALSE;

    TOTPPrevCurrNext(&Prev, &Curr, &Next, "sha1", Secret, ENCODE_BASE32, 6, 30);

    if (strcmp(Response, Prev)==0) RetVal=TRUE;
    if (strcmp(Response, Curr)==0) RetVal=TRUE;
    if (strcmp(Response, Next)==0) RetVal=TRUE;

    Destroy(Prev);
    Destroy(Curr);
    Destroy(Next);

    return(RetVal);
}


int OTPProcess(STREAM *StdIn, const char *Secret)
{
    char *Code=NULL, *Tempstr=NULL;
    int RetVal=FALSE;

    printf("Enter 6-digit TOTP/Authenticator code\n");
    Tempstr=STREAMReadLine(Tempstr, StdIn);
    StripLeadingWhitespace(Tempstr);
    StripTrailingWhitespace(Tempstr);

    if (OTPCheck(Secret, Tempstr))
    {
        printf("Authenticated with OTP\n");
        RetVal=TRUE;
    }
    else
    {
        LogMessage("OTP authentication failed", "");
        printf("OTP Code Input failed\n");
    }

    Destroy(Tempstr);
    Destroy(Code);

    return(RetVal);
}


int ChallengeResponseProcess(STREAM *StdIn, const char *Secret)
{
    char *Code=NULL, *Nonce=NULL, *Tempstr=NULL;
    int RetVal=FALSE;

    Nonce=GetRandomAlphabetStr(Nonce, 16);
    printf("Append password to the below challenge, hash it all with sha1, base64 encode the hash, and enter the result\n");
    printf("challenge: %s\n", Nonce);

    Tempstr=MCopyStr(Tempstr, Nonce, Secret, NULL);
    HashBytes(&Code, "sha1", Tempstr, StrLen(Tempstr), ENCODE_BASE64);

    Tempstr=STREAMReadLine(Tempstr, StdIn);
    StripLeadingWhitespace(Tempstr);
    StripTrailingWhitespace(Tempstr);

    if (StrValid(Tempstr))
    {
        if (strcmp(Tempstr, Code)==0)
        {
            printf("Authenticated...\n");
            RetVal=TRUE;
        }
        else
        {
            LogMessage("Challenge/Response authentication failed", "");
            printf("Authentication failed\n");
        }
    }


    Destroy(Tempstr);
    Destroy(Code);

    return(RetVal);
}


int ProcessAuthentications(const char *Cmd, TProcSettings *Settings)
{
char *Path=NULL, *Hash=NULL;
int result=TRUE;

    if (StrValid(Settings->OTP))
    {
        if (! OTPProcess(StdIn, Settings->OTP)) return(FALSE);
    }

    if (StrValid(Settings->Challenge))
    {
        if (! ChallengeResponseProcess(StdIn, Settings->Challenge)) return(FALSE);
    }

		//
		if ( StrValid(Cmd) && StrValid(Settings->SHA256) )
		{
			GetToken(Cmd, "\\S", &Path, 0);

      HashFile(&Hash, "sha256", Path, ENCODE_HEX);
		  if (strcasecmp(Hash, Settings->SHA256) !=0) 
			{
				Hash=MCopyStr(Hash, "refusing to run ", Path, NULL);
        LogMessage(Hash, "SHA256 hash does not match expected");
				result=FALSE;
			}
		}

		Destroy(Hash);
		Destroy(Path);

    return(result);
}


int ApplyRestrictions(const char *Cmd, TProcSettings *Settings)
{
    if (ProcessAuthentications(Cmd, Settings))
    {
        ProcessSetupRestrictions(Settings);
        return(TRUE);
    }

    return(FALSE);
}



char *ExecSetupCommandLine(char *Cmd, const char *Request, TProcSettings *Settings)
{
    char *Token=NULL;
    const char *ptr;

    ptr=GetToken(Request, "\\S", &Token, 0);

    if (StrValid(Settings->Args)) Cmd=MCopyStr(Cmd, Token, " ", Settings->Args, NULL);
    else Cmd=CopyStr(Cmd, Request);

    Destroy(Token);

    return(Cmd);
}


void ExecCommand(const char *Request, const char *Config)
{
    TProcSettings *Settings;
    char *Cmd=NULL;

    Settings=ProcessSettingsNew(Config);
    Cmd=ExecSetupCommandLine(Cmd, Request, Settings);
    if (ApplyRestrictions(Cmd, Settings)) SwitchProgram(Cmd, "");

    //if we get here, then ´plyRestrictions´ failed, and we never ran the process

    ProcSettingsDestroy(Settings);

    Destroy(Cmd);
}


void PerformRequest(const char *Request)
{
    ListNode *Match;
    char *Cmd=NULL, *Token=NULL;
    const char *ptr;

    Match=RequestFindMatch(Request);
    if (Match)
    {
        //Replace the requested command, with the match that we found.
        //The match will have a full path, so we will be replacing the command
        //with the first one we find that matches and is allowed
        ptr=GetToken(Request, "\\S", &Token, 0);
        Cmd=MCopyStr(Cmd, Match->Tag, " ", ptr, NULL);
        ExecCommand(Cmd, (const char *) Match->Item);
    }
    else
    {
        if (! StrValid(Request)) LogMessage("unexpected request", "<none> (basic shell)");
        else LogMessage("unexpected request", Request);

        printf("permission denied\n");
        fflush(NULL);
    }

    Destroy(Token);
    Destroy(Cmd);
}


void SpawnRequest(const char *Request)
{
    pid_t pid;

    pid=fork();
    if (pid == 0)
    {
        PerformRequest(Request);
        _exit(0);
    }
    else waitpid(pid, NULL, 0);
}


void InteractiveMode()
{
    char *Request=NULL, *Tempstr=NULL;
    double LastRead=0;

    LastRead=GetTime(0);
    Tempstr=STREAMReadLine(Tempstr, StdIn);
    while (Request)
    {
        if (StrValid(Request))
        {
            LastRead=GetTime(0);
            Request=MakeShellSafeString(Request, Tempstr, SHELLSAFE_BLANK);
            if (strcmp(Request, Tempstr) !=0) LogMessage("shell unsafe command on stdin:", Tempstr);

            // in interactive mode we fire off a subprocess to run the command
            SpawnRequest(Request);
        }
        else
        {
            if (
                (GlobalSettings.Timeout > 0) &&
                ( (GetTime(0) - LastRead) > GlobalSettings.Timeout)
            ) break;
        }

        Tempstr=STREAMReadLine(Tempstr, StdIn);
    }

    Destroy(Request);
    Destroy(Tempstr);
}



void MenuMode()
{
    ListNode *Options, *Curr, *Choice;
    TProcSettings *Item;
    char *Cmd=NULL;

    Options=ListCreate();
    Curr=ListGetNext(Rules);
    while (Curr)
    {

        if (strcmp(Curr->Tag, "narrowsh") !=0)
        {
            Item=(TProcSettings *) calloc(1, sizeof(TProcSettings));
            Item->Cmd=CopyStr(Item->Cmd, Curr->Tag);
            ProcessParseSettings(Item, (const char *) Curr->Item);

            if (StrValid(Item->Title)) ListAddNamedItem(Options, Item->Title, Item);
            else ListAddNamedItem(Options, Curr->Tag, Item);
        }

        Curr=ListGetNext(Curr);
    }


//Only 2 ways out of this loop:
// 1) FLAG_ONESHOT is set, so we switch to the requested app, and exit when it does
// 2) User selects 'exit' option
    while (1)
    {
        //must re-init terminal every time, as previous apps we ran might leave it in any state
        TerminalInit(StdIn, TERM_SAVE_ATTRIBS|TERM_RAWKEYS);
        TerminalClear(StdIn);
        TerminalCursorMove(StdIn, 0,0);
        if (StrValid(GlobalSettings.Banner)) TerminalPrint(StdIn, "%s\n", GlobalSettings.Banner);
        Choice=TerminalMenu(StdIn, Options, 1, 4, 40, 10);
        TerminalReset(StdIn);

        if (Choice)
        {
            printf("\r\n");
            fflush(NULL);
            Item=(TProcSettings *) Choice->Item;
            Cmd=CopyStr(Cmd, Item->Cmd);
            if (strcmp(Cmd, "exit")==0) break;

            if (StrValid(Cmd))
            {
                if (GlobalSettings.Flags & FLAG_ONESHOT) PerformRequest(Cmd);
                else SpawnRequest(Cmd);
            }
        }
    }

//do not destroy items in this list, as they are
//also in the global 'rules' list
    ListDestroy(Options, NULL);

    Destroy(Cmd);
}


int main(int argc, char *argv[])
{
    char *Request=NULL;

    setsid();
    memset(&GlobalSettings, 0, sizeof(GlobalSettings));
    StdIn=STREAMFromDualFD(0,1);
    RulesDir=CopyStr(RulesDir, "/etc/narrowsh/");

    Request=ParseCommandLine(Request, argc, argv);
    LoadConfig();

    if (GlobalSettings.Timeout > 0) STREAMSetTimeout(StdIn, GlobalSettings.Timeout * 100);

    //perform any top-level authentications if those exist
    if (ProcessAuthentications(NULL, &GlobalSettings))
    {
        if (StrValid(Request)) PerformRequest(Request);
        else if (GlobalSettings.Flags & FLAG_MENU) MenuMode();
        else if (GlobalSettings.Flags & FLAG_INTERACTIVE) InteractiveMode();
    }

    STREAMClose(StdIn);
    Destroy(Request);
}
