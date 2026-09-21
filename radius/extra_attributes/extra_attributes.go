// Package extraAttributes реализует установку дополнительных RADIUS-атрибутов
// в ответ по полному имени - используется как бэкенд для
// events.AuthResponse.ExtraAttributes, чтобы не заводить под каждое новое
// имя атрибута отдельную Go-функцию. Вендор для каждого имени хранится прямо в
// реестре (см. attrTypes), а не выводится разбором префикса строки - так надёжнее
// и не требует отдельной таблицы "префикс -> vendor id" в синхроне с основной.
// Новые атрибуты (в том числе других вендоров) достаточно дописать в attrTypes,
// без изменений в вызывающем коде.
package extraAttributes

import (
	"fmt"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

const (
	vendorMikrotik uint32 = 14988
	vendorRedback  uint32 = 2352
)

type attrInfo struct {
	VendorID uint32
	Type     byte
}

// attrTypes - полное имя атрибута -> вендор и тип внутри него. Включены только
// атрибуты типа string - SetString умеет кодировать только строки.
//
// MikroTik (vendor 14988) сверен с официальным dictionary.mikrotik
// (github.com/FreeRADIUS/freeradius-server/blob/master/share/dictionary/radius/dictionary.mikrotik,
// идентичен vendors/mikrotik/dictionary.mikrotik из layeh.com/radius). Не включены
// integer/ipaddr атрибуты (Recv-Limit, Xmit-Limit, Wireless-Forward, Wireless-Skip-Dot1x,
// Wireless-Enc-Algo, Host-IP, Advertise-Interval, Recv/Xmit-Limit-Gigawords, Total-Limit,
// Total-Limit-Gigawords, Wireless-VLANID, Wireless-VLANID-Type) - через SetString их
// корректно не закодировать, под них при необходимости нужен отдельный сеттер.
//
// Redback (vendor 2352) - типы сверены с radius/redback (сгенерированным пакетом
// с полным словарём Redback), добавлен как пример второго вендора.
var attrTypes = map[string]attrInfo{
	"Mikrotik-Group":                  {vendorMikrotik, 3},
	"Mikrotik-Wireless-Enc-Key":       {vendorMikrotik, 7},
	"Mikrotik-Rate-Limit":             {vendorMikrotik, 8},
	"Mikrotik-Realm":                  {vendorMikrotik, 9},
	"Mikrotik-Mark-Id":                {vendorMikrotik, 11},
	"Mikrotik-Advertise-URL":          {vendorMikrotik, 12},
	"Mikrotik-Wireless-PSK":           {vendorMikrotik, 16},
	"Mikrotik-Address-List":           {vendorMikrotik, 19},
	"Mikrotik-Wireless-MPKey":         {vendorMikrotik, 20},
	"Mikrotik-Wireless-Comment":       {vendorMikrotik, 21},
	"Mikrotik-Delegated-IPv6-Pool":    {vendorMikrotik, 22},
	"Mikrotik-DHCP-Option-Set":        {vendorMikrotik, 23},
	"Mikrotik-DHCP-Option-Param-STR1": {vendorMikrotik, 24},
	"Mikrotik-DHCP-Option-ParamSTR2":  {vendorMikrotik, 25},
	"Mikrotik-Wireless-Minsignal":     {vendorMikrotik, 28},
	"Mikrotik-Wireless-Maxsignal":     {vendorMikrotik, 29},
	"Mikrotik-Switching-Filter":       {vendorMikrotik, 30},

	"Redback-Context-Name": {vendorRedback, 4},
}

func addVendor(p *radius.Packet, vendorID uint32, typ byte, attr radius.Attribute) error {
	vendor := make(radius.Attribute, 2+len(attr))
	vendor[0] = typ
	vendor[1] = byte(len(vendor))
	copy(vendor[2:], attr)
	vsa, err := radius.NewVendorSpecific(vendorID, vendor)
	if err != nil {
		return err
	}
	p.Add(rfc2865.VendorSpecific_Type, vsa)
	return nil
}

// SetString добавляет в ответ атрибут name=value. name - полное имя атрибута
// (например "Mikrotik-Address-List" или "Redback-Context-Name"), должно быть
// заранее зарегистрировано в attrTypes - вендор определяется по нему автоматически.
func SetString(p *radius.Packet, name, value string) error {
	info, ok := attrTypes[name]
	if !ok {
		return fmt.Errorf("unknown attribute %q", name)
	}
	a, err := radius.NewString(value)
	if err != nil {
		return err
	}
	return addVendor(p, info.VendorID, info.Type, a)
}
