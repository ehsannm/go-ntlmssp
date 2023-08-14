package ntlmssp

type negotiateFlags uint32

const (
    FlagNTLMSSPNEGOTIATEUNICODE                 negotiateFlags = 1 << 0
    FlagNTLMNEGOTIATEOEM                                       = 1 << 1
    FlagNTLMSSPREQUESTTARGET                                   = 1 << 2
    FlagNTLMSSPNEGOTIATESIGN                                   = 1 << 4
    FlagNTLMSSPNEGOTIATESEAL                                   = 1 << 5
    FlagNTLMSSPNEGOTIATEDATAGRAM                               = 1 << 6
    FlagNTLMSSPNEGOTIATELMKEY                                  = 1 << 7
    FlagNTLMSSPNEGOTIATENTLM                                   = 1 << 9
    FlagANONYMOUS                                              = 1 << 11
    FlagNTLMSSPNEGOTIATEOEMDOMAINSUPPLIED                      = 1 << 12
    FlagNTLMSSPNEGOTIATEOEMWORKSTATIONSUPPLIED                 = 1 << 13
    FlagNTLMSSPNEGOTIATEALWAYSSIGN                             = 1 << 15
    FlagNTLMSSPTARGETTYPEDOMAIN                                = 1 << 16
    FlagNTLMSSPTARGETTYPESERVER                                = 1 << 17
    FlagNTLMSSPNEGOTIATEEXTENDEDSESSIONSECURITY                = 1 << 19
    FlagNTLMSSPNEGOTIATEIDENTIFY                               = 1 << 20
    FlagNTLMSSPREQUESTNONNTSESSIONKEY                          = 1 << 22
    FlagNTLMSSPNEGOTIATETARGETINFO                             = 1 << 23
    FlagNTLMSSPNEGOTIATEVERSION                                = 1 << 25
    FlagNTLMSSPNEGOTIATE128                                    = 1 << 29
    FlagNTLMSSPNEGOTIATEKEYEXCH                                = 1 << 30
    FlagNTLMSSPNEGOTIATE56                                     = 1 << 31
)

func (field negotiateFlags) Has(flags negotiateFlags) bool {
    return field&flags == flags
}

func (field *negotiateFlags) Unset(flags negotiateFlags) {
    *field = *field ^ (*field & flags)
}
