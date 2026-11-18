package top.egon.cola.platform.tianquan.shoubing.starter.client;

import org.mapstruct.Mapper;
import org.mapstruct.ReportingPolicy;
import org.mapstruct.factory.Mappers;
import top.egon.cola.component.common.core.converter.BaseForwardConverter;

/** Projects a deployment binding to a validated immutable destination. */
@Mapper(unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface IdpTransportBindingConverter
        extends BaseForwardConverter<IdpTransportBindingProperties.Binding, IdpTransportBindingVO> {

    IdpTransportBindingConverter INSTANCE = Mappers.getMapper(IdpTransportBindingConverter.class);

    @Override
    IdpTransportBindingVO toTarget(IdpTransportBindingProperties.Binding source);
}
