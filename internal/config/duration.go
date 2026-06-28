package config

import "time"

func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var raw any
	if err := unmarshal(&raw); err != nil {
		return err
	}
	switch value := raw.(type) {
	case int:
		*d = Duration(time.Duration(value))
	case string:
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		*d = Duration(parsed)
	}
	return nil
}

type Duration time.Duration

func (d Duration) Std() time.Duration {
	return time.Duration(d)
}
