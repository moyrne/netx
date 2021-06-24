package netx

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/pkg/errors"
	"net"
	"strings"
)

func NewDNSMessage(buffer *bytes.Buffer) (*DNSMessage, error) {
	// 用bytes.Buffer类型来逐个字节读取后处理的优点就是不需要自己计算读取偏移值
	// 这个对于Question和Answer这种第一段长度不固定的内容处理非常方便

	dnsMsg := &DNSMessage{
		Header: &DNSHeader{
			TxID: 0,
			Flags: &DNSFlags{
				QR:     0,
				OpCode: 0,
				AA:     0,
				TC:     0,
				RD:     0,
				RA:     0,
				Z:      0,
				RCode:  0,
			},
			Questions:     0,
			AnswerRRs:     0,
			AuthorityRRs:  0,
			AdditionalRRs: 0,
		},
	}

	question, err := NewDNSQuestion(buffer)
	if err != nil {
		return nil, err
	}

	dnsMsg.Questions = append(dnsMsg.Questions, question)
	if buffer.Len() > 0 {
		recode, err := NewDNSResourceRecode(buffer)
		if err != nil {
			return nil, err
		}
		dnsMsg.ResourceRecodes = append(dnsMsg.ResourceRecodes, recode)
	}

	return dnsMsg, nil
}

func NewDNSResourceRecode(buffer *bytes.Buffer) (*DNSResourceRecode, error) {
	tag := buffer.Next(1)[0] >> 6
	if err := buffer.UnreadByte(); err != nil {
		return nil, err
	}
	r := &DNSResourceRecode{}
	if tag == 3 {
		// 最高两位11，右移后是3
		r.NamePos = (binary.BigEndian.Uint16(buffer.Next(2)) << 2) >> 2
	}
	r.RRType = binary.BigEndian.Uint16(buffer.Next(2))
	r.Class = binary.BigEndian.Uint16(buffer.Next(2))
	r.TTL = binary.BigEndian.Uint32(buffer.Next(4))
	r.RDLength = binary.BigEndian.Uint16(buffer.Next(2))

	if r.RRType == 1 && r.RDLength == 4 {
		r.RData = net.IPv4(buffer.Next(1)[0], buffer.Next(1)[0], buffer.Next(1)[0], buffer.Next(1)[0]).String()
	} else {
		fmt.Println("[rdata]", string(buffer.Next(int(r.RDLength))))
		// FIXME:
		// 域名处理
	}

	return r, nil
}

func NewDNSQuestion(buffer *bytes.Buffer) (*DNSQuestion, error) {
	// 8bit标记每一级域名的长度
	// buf := bytes.NewBuffer(data)
	length := uint8(0)
	if err := binary.Read(buffer, binary.BigEndian, &length); err != nil {
		return nil, errors.WithMessage(err, "read length")
	}
	var segments []string
	for length > 0 {
		seg := make([]byte, length)
		if err := binary.Read(buffer, binary.BigEndian, &seg); err != nil {
			return nil, errors.WithMessage(err, "read seg")
		}
		segments = append(segments, string(seg))
		if err := binary.Read(buffer, binary.BigEndian, &length); err != nil {
			return nil, errors.WithMessage(err, "read length")
		}
	}

	question := &DNSQuestion{
		QuestionName: strings.Join(segments, "."),
	}

	question.QuestionType = binary.BigEndian.Uint16(buffer.Next(2))
	question.QuestionClass = binary.BigEndian.Uint16(buffer.Next(2))

	return question, nil
}

func NewDNSHeader(buffer *bytes.Buffer) *DNSHeader {
	id := binary.BigEndian.Uint16(buffer.Next(2))
	flag := binary.BigEndian.Uint16(buffer.Next(2))
	return &DNSHeader{
		TxID: id,
		Flags: &DNSFlags{
			QR:     flag >> 15,
			OpCode: (flag >> 11) % (1 << 4),
			AA:     (flag >> 10) % (1 << 1),
			TC:     (flag >> 9) % (1 << 1),
			RD:     (flag >> 8) % (1 << 1),
			RA:     (flag >> 7) % (1 << 1),
			Z:      (flag >> 4) % (1 << 3),
			RCode:  flag % (1 << 4),
		},
		Questions:     binary.BigEndian.Uint16(buffer.Next(2)),
		AnswerRRs:     binary.BigEndian.Uint16(buffer.Next(2)),
		AuthorityRRs:  binary.BigEndian.Uint16(buffer.Next(2)),
		AdditionalRRs: binary.BigEndian.Uint16(buffer.Next(2)),
	}
}
