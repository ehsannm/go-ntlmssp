package ntlmssp

type negotiateFlags uint32

const (
    negotiateFlagNTLMSSPNEGOTIATEUNICODE                 negotiateFlags = 1 << 0
    negotiateFlagNTLMNEGOTIATEOEM                                       = 1 << 1
    negotiateFlagNTLMSSPREQUESTTARGET                                   = 1 << 2
    negotiateFlagNTLMSSPNEGOTIATESIGN                                   = 1 << 4
    negotiateFlagNTLMSSPNEGOTIATESEAL                                   = 1 << 5
    negotiateFlagNTLMSSPNEGOTIATEDATAGRAM                               = 1 << 6
    negotiateFlagNTLMSSPNEGOTIATELMKEY                                  = 1 << 7
    negotiateFlagNTLMSSPNEGOTIATENTLM                                   = 1 << 9
    negotiateFlagANONYMOUS                                              = 1 << 11
    negotiateFlagNTLMSSPNEGOTIATEOEMDOMAINSUPPLIED                      = 1 << 12
    negotiateFlagNTLMSSPNEGOTIATEOEMWORKSTATIONSUPPLIED                 = 1 << 13
    negotiateFlagNTLMSSPNEGOTIATEALWAYSSIGN                             = 1 << 15
    negotiateFlagNTLMSSPTARGETTYPEDOMAIN                                = 1 << 16
    negotiateFlagNTLMSSPTARGETTYPESERVER                                = 1 << 17
    negotiateFlagNTLMSSPNEGOTIATEEXTENDEDSESSIONSECURITY                = 1 << 19
    negotiateFlagNTLMSSPNEGOTIATEIDENTIFY                               = 1 << 20
    negotiateFlagNTLMSSPREQUESTNONNTSESSIONKEY                          = 1 << 22
    negotiateFlagNTLMSSPNEGOTIATETARGETINFO                             = 1 << 23
    negotiateFlagNTLMSSPNEGOTIATEVERSION                                = 1 << 25
    negotiateFlagNTLMSSPNEGOTIATE128                                    = 1 << 29
    negotiateFlagNTLMSSPNEGOTIATEKEYEXCH                                = 1 << 30
    negotiateFlagNTLMSSPNEGOTIATE56                                     = 1 << 31
)

func (field negotiateFlags) Has(flags negotiateFlags) bool {
    return field&flags == flags
}

func (field *negotiateFlags) Unset(flags negotiateFlags) {
    *field = *field ^ (*field & flags)
}
