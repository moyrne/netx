package netx

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"net"
	"strconv"
	"strings"
)

func LookUp(serviceIP, host string) (string, error) {
	conn, err := net.Dial("udp", serviceIP)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	msg := &DNSMessage{
		Header: &DNSHeader{
			TxID: 1,
			Flags: &DNSFlags{
				RD: 1,
			},
			Questions: 1,
		},
		Questions: []*DNSQuestion{
			{
				QuestionName:  host,
				QuestionType:  DNSTypeA,
				QuestionClass: DNSClassIn,
			},
		},
	}

	toByte, err := msg.ToByte()
	if err != nil {
		return "", err
	}

	if _, err := conn.Write(toByte); err != nil {
		return "", err
	}
	buf := make([]byte, 1024)

	length, err := conn.Read(buf)
	if err != nil {
		return "", err
	}

	result, err := NewDNSMessage(bytes.NewBuffer(buf[0:length]))
	if err != nil {
		return "", err
	}
	marshal, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	fmt.Println(string(marshal))
	return "", nil
}

type DNSMessage struct {
	Header          *DNSHeader
	Questions       []*DNSQuestion
	ResourceRecodes []*DNSResourceRecode
}

func (d *DNSMessage) ToByte() ([]byte, error) {
	var buffer bytes.Buffer
	header, err := d.Header.ToByte()
	if err != nil {
		return nil, errors.WithMessage(err, "get header error")
	}
	buffer.Write(header)
	for i := uint16(0); i < d.Header.Questions; i++ {
		question, err := d.Questions[i].ToByte()
		if err != nil {
			return nil, errors.WithMessage(err, "write question error")
		}
		buffer.Write(question)
	}
	for _, recode := range d.ResourceRecodes {
		toByte, err := recode.ToByte()
		if err != nil {
			return nil, errors.WithMessage(err, "write resource error")
		}
		buffer.Write(toByte)
	}
	return buffer.Bytes(), nil
}

type DNSHeader struct {
	TxID uint16 // DNS 报文的 ID 标识

	// Flags
	Flags *DNSFlags

	Questions     uint16 // 问题计数
	AnswerRRs     uint16 // 回答资源记录数
	AuthorityRRs  uint16 // 权威名称服务器计数
	AdditionalRRs uint16 // 附加资源记录数
}

func (h *DNSHeader) ToByte() ([]byte, error) {
	var buffer bytes.Buffer
	for i, u := range [6]uint16{h.TxID, h.Flags.ToBit(), h.Questions, h.AnswerRRs, h.AuthorityRRs, h.AdditionalRRs} {
		if err := binary.Write(&buffer, binary.BigEndian, u); err != nil {
			return nil, errors.WithMessage(err, "header error index: "+strconv.Itoa(i))
		}
	}
	return buffer.Bytes(), nil
}

type DNSFlags struct {
	QR     uint16 // 请求/响应的标志信息. 请求:0; 响应:1
	OpCode uint16 // 0:标准查询; 1:反向查询; 2:服务器状态
	AA     uint16 // 授权应答, 响应报文中有效. 1:权威服务器; 0:非权威服务器
	TC     uint16 // 是否被截断. 1:响应超过 512 字节被截断, 只返回前512字节
	RD     uint16 // 期望递归.
	RA     uint16 // 可用递归. 只出现在响应报文. 1:服务器支持递归查询
	Z      uint16 // 保留字段
	RCode  uint16 /*
		0，没有错误；
		1，报文格式错误, 服务器不能理解请求的报文;
		2，域名服务器失败, 因为服务器的原因导致没办法处理这个请求;
		3，名字错误, 只有对授权域名解析服务器有意义，指出解析的域名不存在;
		4，查询类型不支持, 即域名服务器不支持查询类型;
		5，拒绝, 一般是服务器由于设置的策略拒绝给出应答.
	*/
}

func (f *DNSFlags) ToBit() uint16 {
	return f.QR<<15 + f.OpCode<<11 + f.AA<<10 + f.TC<<9 + f.RD<<8 + f.RA<<7 + f.RCode
}

const (
	DNSTypeA     = 1
	DNSTypeNS    = 2
	DNSTypeCName = 5
	DNSTypeAAAA  = 28 // IPV6
)

type DNSQuestion struct {
	QuestionName  string
	QuestionType  uint16
	QuestionClass uint16
}

func (q *DNSQuestion) ToByte() ([]byte, error) {
	var buffer bytes.Buffer
	for _, seg := range strings.Split(q.QuestionName, ".") {
		if err := binary.Write(&buffer, binary.BigEndian, byte(len(seg))); err != nil {
			return nil, errors.WithMessage(err, "write seg len error")
		}
		if err := binary.Write(&buffer, binary.BigEndian, []byte(seg)); err != nil {
			return nil, errors.WithMessage(err, "write seg error")
		}
	}
	if err := binary.Write(&buffer, binary.BigEndian, byte(0x00)); err != nil {
		return nil, errors.WithMessage(err, "write 0x00 error")
	}

	if err := binary.Write(&buffer, binary.BigEndian, q.QuestionType); err != nil {
		return nil, errors.WithMessage(err, "write question type error")
	}
	if err := binary.Write(&buffer, binary.BigEndian, q.QuestionClass); err != nil {
		return nil, errors.WithMessage(err, "write question class error")
	}
	return buffer.Bytes(), nil
}

const (
	DNSClassIn = 1
)

// DNSResourceRecode 回答字段，授权字段，附加字段
type DNSResourceRecode struct {
	Name     string
	NamePos  uint16
	RRType   uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    string
}

var ErrClassNotSupport = errors.New("this class is not supported")

func (r *DNSResourceRecode) ToByte() ([]byte, error) {
	var buffer bytes.Buffer
	if r.NamePos > 0 {
		if err := binary.Write(&buffer, binary.BigEndian, (0x01<<15)|(0x01<<14)|r.NamePos); err != nil {
			return nil, errors.WithMessage(err, "name pos zero write error")
		}
	}
	if r.NamePos <= 0 {
		segments := strings.Split(r.Name, ".")
		for _, seg := range segments {
			if err := binary.Write(&buffer, binary.BigEndian, byte(len(seg))); err != nil {
				return nil, errors.WithMessage(err, "write seg len error")
			}
			if err := binary.Write(&buffer, binary.BigEndian, []byte(seg)); err != nil {
				return nil, errors.WithMessage(err, "write seg error")
			}
		}
		if err := binary.Write(&buffer, binary.BigEndian, byte(0x00)); err != nil {
			return nil, errors.WithMessage(err, "write 0x00 error")
		}
	}

	if err := binary.Write(&buffer, binary.BigEndian, r.RRType); err != nil {
		return nil, errors.WithMessage(err, "write RRType error")
	}
	if err := binary.Write(&buffer, binary.BigEndian, r.Class); err != nil {
		return nil, errors.WithMessage(err, "write Class error")
	}
	if err := binary.Write(&buffer, binary.BigEndian, r.TTL); err != nil {
		return nil, errors.WithMessage(err, "write TTL error")
	}
	if err := binary.Write(&buffer, binary.BigEndian, r.RDLength); err != nil {
		return nil, errors.WithMessage(err, "RDLength error")
	}

	switch r.Class {
	case DNSClassIn:
		if err := binary.Write(&buffer, binary.BigEndian, []byte(net.ParseIP(r.RData).To4())); err != nil {
			return nil, errors.WithMessage(err, "write RData error")
		}
	default:
		return nil, ErrClassNotSupport
	}

	return buffer.Bytes(), nil
}
