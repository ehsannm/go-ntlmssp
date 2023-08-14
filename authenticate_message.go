package ntlmssp

import (
    "bytes"
    "crypto/rand"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "errors"
    "strings"
    "time"
)

type authenticateMessage struct {
    LmChallengeResponse []byte
    NtChallengeResponse []byte

    TargetName string
    UserName   string

    // only set if negotiateFlag_NTLMSSP_NEGOTIATE_KEY_EXCH
    EncryptedRandomSessionKey []byte

    NegotiateFlags negotiateFlags

    MIC []byte
}

type authenticateMessageFields struct {
    messageHeader
    LmChallengeResponse varField
    NtChallengeResponse varField
    TargetName          varField
    UserName            varField
    Workstation         varField
    _                   [8]byte
    NegotiateFlags      negotiateFlags
}

func (m authenticateMessage) MarshalBinary() ([]byte, error) {
    if !m.NegotiateFlags.Has(FlagNTLMSSPNEGOTIATEUNICODE) {
        return nil, errors.New("only unicode is supported")
    }

    target, user := toUnicode(m.TargetName), toUnicode(m.UserName)
    workstation := toUnicode("")

    ptr := binary.Size(&authenticateMessageFields{})
    f := authenticateMessageFields{
        messageHeader:       newMessageHeader(3),
        NegotiateFlags:      m.NegotiateFlags,
        LmChallengeResponse: newVarField(&ptr, len(m.LmChallengeResponse)),
        NtChallengeResponse: newVarField(&ptr, len(m.NtChallengeResponse)),
        TargetName:          newVarField(&ptr, len(target)),
        UserName:            newVarField(&ptr, len(user)),
        Workstation:         newVarField(&ptr, len(workstation)),
    }

    f.NegotiateFlags.Unset(FlagNTLMSSPNEGOTIATEVERSION)

    b := bytes.Buffer{}
    if err := binary.Write(&b, binary.LittleEndian, &f); err != nil {
        return nil, err
    }
    if err := binary.Write(&b, binary.LittleEndian, &m.LmChallengeResponse); err != nil {
        return nil, err
    }
    if err := binary.Write(&b, binary.LittleEndian, &m.NtChallengeResponse); err != nil {
        return nil, err
    }
    if err := binary.Write(&b, binary.LittleEndian, &target); err != nil {
        return nil, err
    }
    if err := binary.Write(&b, binary.LittleEndian, &user); err != nil {
        return nil, err
    }
    if err := binary.Write(&b, binary.LittleEndian, &workstation); err != nil {
        return nil, err
    }

    return b.Bytes(), nil
}

func (m authenticateMessage) String() string {
    x, _ := json.MarshalIndent(
        map[string]any{
            "LmChallengeResponse":       hex.EncodeToString(m.LmChallengeResponse),
            "NtChallengeResponse":       hex.EncodeToString(m.NtChallengeResponse),
            "TargetName":                m.TargetName,
            "UserName":                  m.UserName,
            "EncryptedRandomSessionKey": hex.EncodeToString(m.EncryptedRandomSessionKey),
            "NegotiateFlags":            m.NegotiateFlags,
            "MIC":                       hex.EncodeToString(m.MIC),
        },
        "",
        "  ",
    )

    return string(x)
}

// processChallenge crafts an AUTHENTICATE message in response to the CHALLENGE message
// that was received from the server
func processChallenge(
        challengeMessageData []byte, user, password string, domainNeeded bool,
) (*authenticateMessage, error) {
    if user == "" && password == "" {
        return nil, errors.New("anonymous authentication not supported")
    }

    var cm challengeMessage
    if err := cm.UnmarshalBinary(challengeMessageData); err != nil {
        return nil, err
    }

    if cm.NegotiateFlags.Has(FlagNTLMSSPNEGOTIATELMKEY) {
        return nil, errors.New("only NTLM v2 is supported, but server requested v1 (NTLMSSP_NEGOTIATE_LM_KEY)")
    }
    if cm.NegotiateFlags.Has(FlagNTLMSSPNEGOTIATEKEYEXCH) {
        return nil, errors.New("key exchange requested but not supported (NTLMSSP_NEGOTIATE_KEY_EXCH)")
    }

    if !domainNeeded {
        cm.TargetName = ""
    }

    am := authenticateMessage{
        UserName:       user,
        TargetName:     cm.TargetName,
        NegotiateFlags: cm.NegotiateFlags,
    }

    timestamp := cm.TargetInfo[avIDMsvAvTimestamp]
    if timestamp == nil { // no time sent, take current time
        ft := uint64(time.Now().UnixNano()) / 100
        ft += 116444736000000000 // add time between unix & windows offset
        timestamp = make([]byte, 8)
        binary.LittleEndian.PutUint64(timestamp, ft)
    }

    clientChallenge := make([]byte, 8)
    _, _ = rand.Reader.Read(clientChallenge)

    ntlmV2Hash := getNtlmV2Hash(password, user, cm.TargetName)

    am.NtChallengeResponse = computeNtlmV2Response(
        ntlmV2Hash,
        cm.ServerChallenge[:],
        clientChallenge,
        timestamp,
        cm.TargetInfoRaw,
    )

    if cm.TargetInfoRaw == nil {
        am.LmChallengeResponse = computeLmV2Response(ntlmV2Hash,
            cm.ServerChallenge[:], clientChallenge)
    }

    return &am, nil
}

func ProcessChallengeWithHash(challengeMessageData []byte, user, hash string) ([]byte, error) {
    if user == "" && hash == "" {
        return nil, errors.New("anonymous authentication not supported")
    }

    var cm challengeMessage
    if err := cm.UnmarshalBinary(challengeMessageData); err != nil {
        return nil, err
    }

    if cm.NegotiateFlags.Has(FlagNTLMSSPNEGOTIATELMKEY) {
        return nil, errors.New("only NTLM v2 is supported, but server requested v1 (NTLMSSP_NEGOTIATE_LM_KEY)")
    }
    if cm.NegotiateFlags.Has(FlagNTLMSSPNEGOTIATEKEYEXCH) {
        return nil, errors.New("key exchange requested but not supported (NTLMSSP_NEGOTIATE_KEY_EXCH)")
    }

    am := authenticateMessage{
        UserName:       user,
        TargetName:     cm.TargetName,
        NegotiateFlags: cm.NegotiateFlags,
    }

    timestamp := cm.TargetInfo[avIDMsvAvTimestamp]
    if timestamp == nil { // no time sent, take current time
        ft := uint64(time.Now().UnixNano()) / 100
        ft += 116444736000000000 // add time between unix & windows offset
        timestamp = make([]byte, 8)
        binary.LittleEndian.PutUint64(timestamp, ft)
    }

    clientChallenge := make([]byte, 8)
    _, _ = rand.Reader.Read(clientChallenge)

    hashParts := strings.Split(hash, ":")
    if len(hashParts) > 1 {
        hash = hashParts[1]
    }
    hashBytes, err := hex.DecodeString(hash)
    if err != nil {
        return nil, err
    }
    ntlmV2Hash := hmacMd5(hashBytes, toUnicode(strings.ToUpper(user)+cm.TargetName))

    am.NtChallengeResponse = computeNtlmV2Response(ntlmV2Hash,
        cm.ServerChallenge[:], clientChallenge, timestamp, cm.TargetInfoRaw)

    if cm.TargetInfoRaw == nil {
        am.LmChallengeResponse = computeLmV2Response(ntlmV2Hash,
            cm.ServerChallenge[:], clientChallenge)
    }
    return am.MarshalBinary()
}
