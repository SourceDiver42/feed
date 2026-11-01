rule Sightlines_dotnet_typelib_guid_b1d88192_formbook
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-b1d88192"
        date = "2026-10-27"
        campaign = "dotnet_typelib_guid-b1d88192"
        family = "formbook"
        hash = "34e5887dd33383ebaefa05e6237615463987affd4af6846163fba94221b0b435"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-b1d88192.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Data Source=DESKTOP-BH4JOH6;Initial Catalog=QL_KARAOKE;User ID=sa;Password=123456;Integrated Securit" wide
        $s1 = "Data Source=DESKTOP-BH4JOH6;Initial Catalog=QL_KARAOKE;Integrated Security= True" wide
        $s2 = "StreamingOutput-OBS-VirtualCam,NDI,RTMP,Discord-GoLive,Twitch" ascii
        $s3 = "LatencyEngine3WASAPI-Exclusive,ASIO,DirectSound,Sub-5ms-Roundtrip" ascii
        $s4 = "SongLibrary0CDG,KAR,MIDI,LRC,SRT,MP3+G,MP4,WebM,YouTube-Sync" ascii
        $s5 = "MicrophoneSupport6USB,XLR-Interface,Bluetooth,WirelessUHF,Array,Loopback" ascii
        $s6 = "AudioProcessing8KeyShift-24Semi,TempoStretch,Harmonizer,AutoTune,DeEsser" ascii
        $s7 = "RecordingStudio4MultiTrack,VocalIsolated,MixedMaster,Stems,WAV-24bit" ascii
        $s8 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s9 = "ImportSources6LocalFiles,Spotify-Lyrics,MusicBrainz,CD-Rip,Drag-Drop" ascii
        $s10 = "VideoEngine8Webcam,VirtualBackground,ParticleOverlay,LyricsComposite" ascii
        $s11 = "Localization0EN,JA,KO,ZH,TH,VI,TL,ES,PT,FR,AR,HI,60+Languages" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2783232 and 12 of them
}
